rule days_of_yara_url_2byte
{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  strings:
    $target_string = /https:\/\/github\.com\/100DaysofYARA/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
        uint16be(i) ^ uint16be(i+2) == 0x1c04
        and not for 0x2dfc0 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28 ) : ( 
            uint16be(j) ^ uint16be(j+2) 
        )
        and for 0x2dfbf j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28 ) : ( uint16be(j) ^ uint16be(j+2) )
    )
}