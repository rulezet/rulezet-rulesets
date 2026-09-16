rule _20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1_20160921_ebd0ee36b6a5_1920 {
  meta:
    description = "datamaliciousorder - from files 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash2       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1  = "on f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s2  = "turn \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(" ascii
    $s3  = "urn \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})()," ascii
    $s4  = "rn \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fu" ascii
    $s5  = " f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"G" ascii
    $s6  = "(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(" ascii
    $s7  = "rn \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(fu" ascii
    $s8  = "rn \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(fu" ascii
    $s9  = "),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s10 = "(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}