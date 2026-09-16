rule _20160921_649e29a058d10c3bf9a5a5a06eb3b603_20160921_a39f22c0c39a_3011 {
  meta:
    description = "datamaliciousorder - from files 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "{return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii
    $s2 = "ion f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s3 = "(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})" ascii
    $s4 = "(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "ction f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s6 = "(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s7 = "tion f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}