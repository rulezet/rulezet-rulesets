rule _20160921_378cbd2e27643682973c633e59454f9f_20160921_4bad0ae96eb9_3628 {
  meta:
    description = "datamaliciousorder - from files 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_9b80c329004df146d978cb7b31b22c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash2       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash3       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash4       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash5       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"

  strings:
    $s1 = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s2 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RA" ascii
    $s3 = "eturn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s4 = "\"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s5 = "fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii
    $s6 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}