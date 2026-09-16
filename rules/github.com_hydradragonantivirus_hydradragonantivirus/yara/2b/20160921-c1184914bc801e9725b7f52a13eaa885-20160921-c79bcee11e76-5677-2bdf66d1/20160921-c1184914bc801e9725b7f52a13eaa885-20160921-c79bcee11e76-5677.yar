rule _20160921_c1184914bc801e9725b7f52a13eaa885_20160921_c79bcee11e76_5677 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})()" ascii
    $s2 = "})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f0" ascii
    $s3 = "0(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\"" ascii
    $s4 = "urn \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"PTs\";})(),(fu" ascii
    $s5 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}