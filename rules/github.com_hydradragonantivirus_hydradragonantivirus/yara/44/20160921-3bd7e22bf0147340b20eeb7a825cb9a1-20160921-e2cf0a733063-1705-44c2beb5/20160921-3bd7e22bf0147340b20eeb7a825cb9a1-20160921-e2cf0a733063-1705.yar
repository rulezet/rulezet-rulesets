rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_e2cf0a733063_1705 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1  = "\"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(functi" ascii
    $s2  = "ck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\"" ascii
    $s3  = "urn \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4  = "uck(){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm" ascii
    $s5  = "ction fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s6  = "){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";}" ascii
    $s7  = "uck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo" ascii
    $s8  = "k(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";" ascii
    $s9  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Dc" ascii
    $s10 = "tion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){retur" ascii
    $s11 = "nction fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}