rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_1fb059bf2770_4597 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"

  strings:
    $s1 = "ion f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s2 = "(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s3 = " \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s4 = "urn \"Qz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s5 = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}