rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_884f773b3c24_4892 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1 = "\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s2 = "),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){" ascii
    $s3 = "){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})" ascii
    $s4 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"" ascii
    $s5 = " \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}