rule _20160921_063094039ef79437a260d3dde960797a_20160921_2bac0af1f20f_4248 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"

  strings:
    $s1 = "k(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";" ascii
    $s2 = "ck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq" ascii
    $s3 = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s4 = "{return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(" ascii
    $s5 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}