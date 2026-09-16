rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_b86272ed73ce_3791 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii
    $s2 = "(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";}" ascii
    $s3 = "x\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s4 = "000(){return \"Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt" ascii
    $s5 = "0(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";" ascii
    $s6 = " \"Sj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"DIa\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}