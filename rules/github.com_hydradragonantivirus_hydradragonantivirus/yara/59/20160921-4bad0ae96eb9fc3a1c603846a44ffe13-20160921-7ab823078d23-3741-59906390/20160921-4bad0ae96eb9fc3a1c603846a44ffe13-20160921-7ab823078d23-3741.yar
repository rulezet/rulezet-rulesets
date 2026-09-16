rule _20160921_4bad0ae96eb9fc3a1c603846a44ffe13_20160921_7ab823078d23_3741 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash2       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash3       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1 = "n fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s2 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3 = "\"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s4 = "k(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\"" ascii
    $s5 = "turn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s6 = "})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}