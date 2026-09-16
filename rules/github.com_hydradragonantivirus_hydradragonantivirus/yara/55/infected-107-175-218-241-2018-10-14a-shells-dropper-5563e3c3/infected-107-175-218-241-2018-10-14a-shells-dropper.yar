rule infected_107_175_218_241_2018_10_14a_shells_dropper {
  meta:
    description = "shells - file dropper.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "926034e2fbffb5bbf065c983bb74020fed3db9a8b0c55860df066385a7c0af2b"

  strings:
    $s1 = "MRVNbJ2ZpbGUnXVsnbmFtZSddKSkgeyBlY2hvICc8Yj5VcGxvYWQgQ29tcGxhdGUgISEhPC9iPjxicj4nOyB9IGVjaG8gJzxmb3JtIGFjdGlvbj0iIiBtZXRob2Q9InB" ascii  
    $s2 = "vc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPjxpbnB1dCB0eXBlPSJmaWxlIiBuYW1lPSJmaWxlIiBzaXplPSI1MCI+PGlucHV0IHR5cGU9InN1Ym1pdCI" ascii  
    $s3 = "file_put_contents($fileName, base64_decode($fileData));" fullword ascii
    $s4 = "$fileName = 'sessions.php';" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}