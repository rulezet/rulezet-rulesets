rule _20160921_c1184914bc801e9725b7f52a13eaa885_20160921_e98813a05e66_5675 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "rn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s2 = "nction f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "urn \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s4 = "\"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s5 = "rn \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}