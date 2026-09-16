rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_4809ff267979_2689 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_4809ff2679793c2b9af03e18ec3702ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"

  strings:
    $s1 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Qh\";})(),(functio" ascii
    $s2 = "ck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"ZLd\"" ascii
    $s3 = "n \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ai\";})(),(fun" ascii
    $s4 = " \"Wo0\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii
    $s5 = "){return \"Ik\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";}" ascii
    $s6 = "eturn \"OQr\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s7 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}