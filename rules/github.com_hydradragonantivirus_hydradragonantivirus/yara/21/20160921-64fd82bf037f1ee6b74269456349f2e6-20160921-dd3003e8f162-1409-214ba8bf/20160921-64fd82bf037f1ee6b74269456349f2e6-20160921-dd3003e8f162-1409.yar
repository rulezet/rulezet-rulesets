rule _20160921_64fd82bf037f1ee6b74269456349f2e6_20160921_dd3003e8f162_1409 {
  meta:
    description = "datamaliciousorder - from files 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash2       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1  = "){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s2  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"EHo\";})(),(funct" ascii
    $s3  = "nction fuck(){return \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s4  = "nction fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){" ascii
    $s6  = "urn \"Xg\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(f" ascii
    $s7  = "unction fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii
    $s8  = ")(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s9  = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"LLv\";})(),(func" ascii
    $s10 = "(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii
    $s11 = "ion fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return " ascii
    $s12 = "IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Fv\";})(),(functi" ascii
    $s13 = "k(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";}" ascii
    $s14 = "k(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}