rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_bcf391146213_591 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash3       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash4       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1  = "on f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Q" ascii
    $s2  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){retu" ascii
    $s3  = "n \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s4  = "function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s5  = "00(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Qa" ascii
    $s6  = "return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s7  = "Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function" ascii
    $s8  = "000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tb" ascii
    $s9  = "){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";}" ascii
    $s10 = "){return \"Vu\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})(" ascii
    $s11 = "function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){re" ascii
    $s12 = "rn \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})(),(fu" ascii
    $s13 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s14 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nx\";})(),(fun" ascii
    $s15 = "00(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s16 = "q\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s17 = "eturn \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s18 = "eturn \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})()" ascii
    $s19 = "){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yz\";})(" ascii
    $s20 = "0(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}