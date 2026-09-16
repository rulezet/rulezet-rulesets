rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_66de660457cd_4298 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"

  strings:
    $s1 = "(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";" ascii
    $s2 = "Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s3 = " f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GG" ascii
    $s4 = "nction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s5 = "n\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}