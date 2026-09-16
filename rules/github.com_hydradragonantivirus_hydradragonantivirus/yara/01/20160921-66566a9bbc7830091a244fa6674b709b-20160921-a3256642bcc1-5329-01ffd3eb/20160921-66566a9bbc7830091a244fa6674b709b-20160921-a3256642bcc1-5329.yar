rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_a3256642bcc1_5329 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = " f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go" ascii
    $s2 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(" ascii
    $s3 = "nction f000(){return \"Tb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function f000(){retur" ascii
    $s4 = "return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Rh\";})()" ascii
    $s5 = "})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}