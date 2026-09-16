rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_c1184914bc80_2538 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1 = "n \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(f" ascii
    $s2 = "(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";" ascii
    $s3 = "(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(" ascii
    $s4 = "PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s5 = "eturn \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s6 = "turn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})()," ascii
    $s7 = "(),(function f000(){return \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s8 = "(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}