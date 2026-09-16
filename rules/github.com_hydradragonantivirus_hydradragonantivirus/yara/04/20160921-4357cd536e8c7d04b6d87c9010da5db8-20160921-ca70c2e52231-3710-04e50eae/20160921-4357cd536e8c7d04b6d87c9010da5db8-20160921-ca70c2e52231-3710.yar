rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_ca70c2e52231_3710 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_f11c35e3159325debfd0a307299c4087.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash3       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"
    hash4       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "n f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s2 = "i\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Tn\";})(),(function " ascii
    $s3 = "nction f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){retu" ascii
    $s4 = "urn \"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(fu" ascii
    $s5 = "f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZF" ascii
    $s6 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}