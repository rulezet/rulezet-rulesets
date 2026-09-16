rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_30a55f1f397a_4786 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash3       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash4       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){ret" ascii
    $s2 = "Rx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s3 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function f" ascii
    $s4 = "{return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})" ascii
    $s5 = "tion fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}