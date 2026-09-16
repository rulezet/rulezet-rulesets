rule _20160921_66de660457cd1dcbe458e50b91bafaca_20160921_b4c84c929547_5332 {
  meta:
    description = "datamaliciousorder - from files 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash2       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "turn \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = ")(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(" ascii
    $s3 = "0(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";" ascii
    $s4 = "ion f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s5 = "turn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}