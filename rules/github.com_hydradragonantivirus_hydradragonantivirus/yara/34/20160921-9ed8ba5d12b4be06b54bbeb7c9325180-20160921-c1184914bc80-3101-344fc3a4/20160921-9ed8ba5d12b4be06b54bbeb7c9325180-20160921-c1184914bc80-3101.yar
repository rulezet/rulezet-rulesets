rule _20160921_9ed8ba5d12b4be06b54bbeb7c9325180_20160921_c1184914bc80_3101 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1 = "ion f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"" ascii
    $s2 = "on f000(){return \"UOt\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s3 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f" ascii
    $s4 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s5 = "(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})" ascii
    $s6 = "eturn \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})()" ascii
    $s7 = "{return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}