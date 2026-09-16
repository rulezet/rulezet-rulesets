rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_814859e3f9da_4219 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash3       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";}" ascii
    $s2 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s3 = "rn \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii
    $s4 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s5 = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}