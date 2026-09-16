rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_802181e3d75c_5110 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash3       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = "return \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})()," ascii
    $s2 = "nction f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "){return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";" ascii
    $s4 = "WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s5 = "rn \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}