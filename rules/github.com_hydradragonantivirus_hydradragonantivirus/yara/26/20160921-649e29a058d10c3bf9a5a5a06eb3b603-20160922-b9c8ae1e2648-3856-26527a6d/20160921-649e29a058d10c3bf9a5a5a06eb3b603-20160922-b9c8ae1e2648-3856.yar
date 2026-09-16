rule _20160921_649e29a058d10c3bf9a5a5a06eb3b603_20160922_b9c8ae1e2648_3856 {
  meta:
    description = "datamaliciousorder - from files 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash2       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "urn \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(f" ascii
    $s2 = "){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";}" ascii
    $s3 = "{return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(" ascii
    $s4 = "ction f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){retu" ascii
    $s5 = "ion f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return " ascii
    $s6 = ")(),(function f000(){return \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}