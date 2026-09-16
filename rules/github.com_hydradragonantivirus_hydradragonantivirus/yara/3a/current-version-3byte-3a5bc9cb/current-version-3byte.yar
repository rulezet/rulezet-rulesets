rule current_version_3byte 
{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  strings:
    $target_string = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      ( ( uint32be(i) ^ uint32be(i+3) ) >> 8 ) == 0x271807
      and not for 0x21267b9 j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24, i+27, i+30, i+33, i+36, i+39 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8 
      )
      and for 0x21267b8 j in ( i+0, i+3, i+6, i+9, i+12, i+15, i+18, i+21, i+24, i+27, i+30, i+33, i+36, i+39 ) : ( 
        ( uint32be(j) ^ uint32be(j+3) ) >> 8
      )
    )
}