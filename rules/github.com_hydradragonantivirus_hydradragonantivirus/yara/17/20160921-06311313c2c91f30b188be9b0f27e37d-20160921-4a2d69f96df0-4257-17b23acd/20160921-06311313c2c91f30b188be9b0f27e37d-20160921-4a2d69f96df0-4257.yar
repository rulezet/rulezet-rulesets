rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_4257 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1 = "000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s2 = "Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s3 = "n \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s4 = "eturn \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s5 = "(),(function f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}