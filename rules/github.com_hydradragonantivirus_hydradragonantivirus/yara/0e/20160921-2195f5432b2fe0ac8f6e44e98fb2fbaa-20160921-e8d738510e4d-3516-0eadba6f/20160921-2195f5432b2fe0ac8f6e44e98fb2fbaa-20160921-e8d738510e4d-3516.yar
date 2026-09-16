rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_e8d738510e4d_3516 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = ";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck" ascii
    $s2 = "\"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s3 = "),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s4 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"" ascii
    $s5 = "Hj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function" ascii
    $s6 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}