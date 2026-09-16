rule _20160921_b062b54e33ac394b0c1a389b161f5cb6_20160921_c1184914bc80_5638 {
  meta:
    description = "datamaliciousorder - from files 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s2 = "){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return" ascii
    $s4 = "unction f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s5 = "n f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"K" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}