rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_4357cd536e8c_3443 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash3       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash4       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash5       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash6       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash7       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash8       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "Kl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2 = "(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s3 = "){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})" ascii
    $s4 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f0" ascii
    $s5 = "tion f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6 = "000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"QDg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}