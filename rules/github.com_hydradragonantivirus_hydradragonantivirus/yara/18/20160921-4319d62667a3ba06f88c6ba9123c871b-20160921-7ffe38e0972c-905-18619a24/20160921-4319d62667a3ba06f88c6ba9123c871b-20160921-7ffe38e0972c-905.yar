rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_7ffe38e0972c_905 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash3       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash4       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1  = "unction f000(){return \"Ml\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s2  = "0(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s3  = "b\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function" ascii
    $s4  = ",(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){" ascii
    $s5  = ",(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s6  = "function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s7  = "0(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn" ascii
    $s8  = " \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(func" ascii
    $s9  = "turn \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})()," ascii
    $s10 = "0(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s11 = "return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s12 = "n \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s13 = "){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s14 = "000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn" ascii
    $s15 = "(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";" ascii
    $s16 = "){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";}" ascii
    $s17 = "ction f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s18 = "{return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})" ascii
    $s19 = "QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(functio" ascii
    $s20 = "00(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}