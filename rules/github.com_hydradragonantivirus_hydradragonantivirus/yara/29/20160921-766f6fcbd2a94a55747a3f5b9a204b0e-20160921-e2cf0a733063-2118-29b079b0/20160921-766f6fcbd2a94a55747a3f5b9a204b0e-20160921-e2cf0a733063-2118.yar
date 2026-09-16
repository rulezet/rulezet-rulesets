rule _20160921_766f6fcbd2a94a55747a3f5b9a204b0e_20160921_e2cf0a733063_2118 {
  meta:
    description = "datamaliciousorder - from files 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash2       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = "{return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";}" ascii
    $s2 = "})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuc" ascii
    $s3 = "),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s4 = "urn \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(" ascii
    $s5 = "fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"S" ascii
    $s6 = "Pu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function" ascii
    $s7 = "rn \"Qh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(func" ascii
    $s8 = "uck(){return \"Bz\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"IPu\"" ascii
    $s9 = "u\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}