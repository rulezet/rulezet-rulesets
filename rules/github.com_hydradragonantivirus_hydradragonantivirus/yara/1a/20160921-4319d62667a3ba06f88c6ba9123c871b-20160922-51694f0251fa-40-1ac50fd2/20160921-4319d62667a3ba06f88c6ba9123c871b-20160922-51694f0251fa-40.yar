rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160922_51694f0251fa_40 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash3       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1  = "{return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})" ascii
    $s2  = "{return \"Nx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})" ascii
    $s3  = "eturn \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})()" ascii
    $s4  = "function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s5  = "urn \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s6  = "ction f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Wb\";})(),(function f000(){retur" ascii
    $s7  = " f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GG" ascii
    $s8  = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Oh\";})()" ascii
    $s9  = "ion f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s10 = "(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii
    $s11 = "\"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Sj\";})(),(func" ascii
    $s12 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s13 = ",(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){r" ascii
    $s14 = "(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s15 = "ction f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){retur" ascii
    $s16 = "return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})()" ascii
    $s17 = "i\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s18 = ",(function f000(){return \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s19 = "n f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s20 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}