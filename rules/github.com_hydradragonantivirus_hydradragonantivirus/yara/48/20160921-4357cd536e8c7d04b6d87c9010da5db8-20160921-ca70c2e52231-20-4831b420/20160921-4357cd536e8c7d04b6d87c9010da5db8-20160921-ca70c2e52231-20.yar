rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_ca70c2e52231_20 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash3       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1  = "urn \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s2  = "000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc" ascii
    $s3  = " \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(func" ascii
    $s4  = "t\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s5  = "function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Yv\";})(),(function f000(){ret" ascii
    $s6  = "f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn" ascii
    $s7  = "function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(function f000(){ret" ascii
    $s8  = "return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lo\";})()" ascii
    $s9  = "OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s10 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s11 = "\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function " ascii
    $s12 = " f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"K" ascii
    $s13 = "nction f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s14 = "000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um" ascii
    $s15 = "on f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"" ascii
    $s16 = "TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s17 = "ion f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii
    $s18 = ",(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s19 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s20 = "urn \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}