rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_4809ff267979_4810 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_4809ff2679793c2b9af03e18ec3702ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"

  strings:
    $s1 = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jg\";}" ascii
    $s2 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s3 = "return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s4 = "g\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s5 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}