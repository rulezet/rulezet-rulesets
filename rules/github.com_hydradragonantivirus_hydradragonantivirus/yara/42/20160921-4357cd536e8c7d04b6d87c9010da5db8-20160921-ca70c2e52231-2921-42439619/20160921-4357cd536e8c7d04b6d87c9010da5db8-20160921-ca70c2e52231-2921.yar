rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_ca70c2e52231_2921 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash3       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash4       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = "ction f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s3 = "eturn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTs\";})()" ascii
    $s4 = "0(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe" ascii
    $s5 = "eturn \"ZIi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(" ascii
    $s6 = "ction f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii
    $s7 = "){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}