rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_8aaa596582e2_3942 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "n\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(functio" ascii
    $s2 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f" ascii
    $s3 = "tion f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s4 = "0(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\"" ascii
    $s5 = " \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s6 = "00(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}