rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_e98813a05e66_5505 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "eturn \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})()" ascii
    $s2 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s3 = "nction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s4 = ")(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000()" ascii
    $s5 = "0(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}