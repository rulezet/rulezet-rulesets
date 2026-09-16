rule _20160921_b7400937fc4eb76c7ea3adaa321d7619_20160921_cf2bd9606d39_5653 {
  meta:
    description = "datamaliciousorder - from files 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})()" ascii
    $s2 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f00" ascii
    $s3 = "eturn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})()" ascii
    $s4 = "n \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s5 = "00(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}