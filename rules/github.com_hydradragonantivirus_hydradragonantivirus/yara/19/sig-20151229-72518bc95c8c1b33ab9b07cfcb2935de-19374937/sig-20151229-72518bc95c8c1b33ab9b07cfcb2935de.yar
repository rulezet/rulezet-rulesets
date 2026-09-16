rule sig_20151229_72518bc95c8c1b33ab9b07cfcb2935de {
  meta:
    description = "datamaliciousorder - file 20151229_72518bc95c8c1b33ab9b07cfcb2935de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3974ed15cec90346a6165c6d5eb73f982ee4a4e2fa1019070782223b53b4c8eb"

  strings:
    $s1 = "//}else{mcjmmxxa=0;" fullword ascii
    $s2 = "print (pvtjlgpsa);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}