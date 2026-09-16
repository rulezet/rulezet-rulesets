rule _20160921_7dec24f022af3c1ffe46748172dd6cad_20160921_a210d5e93bf8_1903 {
  meta:
    description = "datamaliciousorder - from files 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash2       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"

  strings:
    $s1  = "(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})" ascii
    $s2  = "(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";" ascii
    $s3  = "on fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return " ascii
    $s4  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s5  = "on fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s6  = "k(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";}" ascii
    $s7  = ";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s8  = "return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s9  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za" ascii
    $s10 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}