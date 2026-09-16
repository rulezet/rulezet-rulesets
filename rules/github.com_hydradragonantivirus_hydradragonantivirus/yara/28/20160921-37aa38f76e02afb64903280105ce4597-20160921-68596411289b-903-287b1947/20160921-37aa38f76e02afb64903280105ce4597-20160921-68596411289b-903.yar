rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_68596411289b_903 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_68596411289b2d10a74a19f9fce4a325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"

  strings:
    $s1  = "Gq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s2  = ")(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3  = "function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){ret" ascii
    $s4  = "n f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"W" ascii
    $s5  = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})()," ascii
    $s6  = "ion f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return" ascii
    $s7  = " \"Vj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(func" ascii
    $s8  = ")(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(" ascii
    $s9  = "turn \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s10 = "f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"K" ascii
    $s11 = "f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GG" ascii
    $s12 = "ction f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii
    $s13 = "00(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"WIj" ascii
    $s14 = " f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s15 = "){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";" ascii
    $s16 = "n \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s17 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})()" ascii
    $s18 = "urn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(f" ascii
    $s19 = "(function f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s20 = "})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}