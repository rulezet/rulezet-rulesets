rule Hacktools_CN_Panda_k {
  meta:
    description = "Disclosed hacktool set - file k.exe"
    author      = "Florian Roth"
    date        = "17.11.14"
    score       = 60
    hash        = "8d1170df533238ac2da7826bd8997917be1e1517"

  strings:
    $s0  = "(http://www.eyuyan.com)" fullword wide
    $s1  = "trin" fullword wide
    $s2  = "FAUL" fullword wide
    $s10 = " program must be run " fullword ascii

  condition:
    all of them
}