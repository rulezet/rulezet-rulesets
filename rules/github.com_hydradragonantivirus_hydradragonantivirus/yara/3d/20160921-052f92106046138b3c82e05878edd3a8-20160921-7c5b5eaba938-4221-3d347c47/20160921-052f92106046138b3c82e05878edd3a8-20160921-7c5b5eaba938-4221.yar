rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_7c5b5eaba938_4221 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash3       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"

  strings:
    $s1 = "rn \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s2 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "n \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s4 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(" ascii
    $s5 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}