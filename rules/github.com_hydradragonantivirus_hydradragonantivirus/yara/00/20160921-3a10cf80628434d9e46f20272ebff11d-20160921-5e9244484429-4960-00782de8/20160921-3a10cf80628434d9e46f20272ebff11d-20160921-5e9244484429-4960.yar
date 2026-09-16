rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_5e9244484429_4960 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_5e9244484429cd897ec88fe97140c29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s2 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s3 = "(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck" ascii
    $s4 = "n \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s5 = "on fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}