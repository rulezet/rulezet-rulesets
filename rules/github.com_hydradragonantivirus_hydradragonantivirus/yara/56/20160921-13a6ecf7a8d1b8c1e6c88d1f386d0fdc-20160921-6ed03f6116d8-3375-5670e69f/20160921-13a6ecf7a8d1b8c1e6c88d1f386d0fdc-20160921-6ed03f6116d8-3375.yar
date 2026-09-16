rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_6ed03f6116d8_3375 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash3       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"

  strings:
    $s1 = "){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";}" ascii
    $s2 = "return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(" ascii
    $s3 = "nction f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s4 = "tion f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s5 = "tion f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s6 = "n f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Q" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}