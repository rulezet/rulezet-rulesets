rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_3362ac3903fc_4398 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_5d6863feab411af8217516a1b111aa40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash3       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";" ascii
    $s2 = "UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(funct" ascii
    $s3 = "0(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s4 = "\"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s5 = "function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}