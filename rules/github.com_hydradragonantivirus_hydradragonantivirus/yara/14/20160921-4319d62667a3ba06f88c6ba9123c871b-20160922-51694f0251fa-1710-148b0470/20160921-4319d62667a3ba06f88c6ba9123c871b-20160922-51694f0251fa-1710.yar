rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160922_51694f0251fa_1710 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_9d6af27348126e594fbe29c3cf568591.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash3       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"
    hash4       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1  = ";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s2  = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s3  = "eturn \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(" ascii
    $s4  = "tion f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return" ascii
    $s5  = "ction f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s6  = "Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(functio" ascii
    $s7  = "n f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s8  = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})()," ascii
    $s9  = "turn \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})()" ascii
    $s10 = "{return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})" ascii
    $s11 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}