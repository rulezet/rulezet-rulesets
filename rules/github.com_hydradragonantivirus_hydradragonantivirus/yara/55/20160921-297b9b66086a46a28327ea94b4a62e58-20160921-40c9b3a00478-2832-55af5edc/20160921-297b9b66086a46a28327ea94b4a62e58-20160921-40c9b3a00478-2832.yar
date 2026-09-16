rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_2832 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = "n\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s2 = "Gn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"IPu\";})(),(function" ascii
    $s3 = ",(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s4 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\"" ascii
    $s5 = "OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s6 = "0(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\"" ascii
    $s7 = "0(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}