rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_0393cc83501a_4119 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash3       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash4       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash5       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})" ascii
    $s2 = "\"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(funct" ascii
    $s3 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s4 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"" ascii
    $s5 = "turn \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"EZu\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}