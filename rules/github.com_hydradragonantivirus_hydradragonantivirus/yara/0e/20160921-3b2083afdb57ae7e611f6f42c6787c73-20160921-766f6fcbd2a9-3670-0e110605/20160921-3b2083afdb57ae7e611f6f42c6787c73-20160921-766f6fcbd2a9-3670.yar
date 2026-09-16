rule _20160921_3b2083afdb57ae7e611f6f42c6787c73_20160921_766f6fcbd2a9_3670 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash2       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash3       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = "Av\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(functi" ascii
    $s2 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck" ascii
    $s3 = "urn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(" ascii
    $s4 = "g\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s5 = "n fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s6 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}