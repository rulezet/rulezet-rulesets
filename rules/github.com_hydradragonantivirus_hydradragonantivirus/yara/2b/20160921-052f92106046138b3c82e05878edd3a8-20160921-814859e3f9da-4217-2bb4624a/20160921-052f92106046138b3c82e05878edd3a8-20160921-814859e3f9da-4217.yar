rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_814859e3f9da_4217 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash3       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = ")(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s2 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy" ascii
    $s3 = "})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuc" ascii
    $s4 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){" ascii
    $s5 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}