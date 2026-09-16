rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_1fb059bf2770_4549 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash3       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1 = "})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(" ascii
    $s2 = "){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";" ascii
    $s3 = "000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DI" ascii
    $s4 = "tion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii
    $s5 = "nction f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}