rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_24 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"

  strings:
    $s1  = ",(function f000(){return \"ZIi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){r" ascii
    $s2  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MMz\";})()," ascii
    $s3  = "urn \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s4  = "\"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s5  = "n \"RVb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s6  = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s7  = "tion f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s8  = "\"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(fun" ascii
    $s9  = "function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s10 = "\"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s11 = " \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s12 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"PTs\";})(),(function f000(){ret" ascii
    $s13 = ";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(function f" ascii
    $s14 = "turn \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(" ascii
    $s15 = " \"DNa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s16 = "00(){return \"TKl\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc" ascii
    $s17 = "f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GG" ascii
    $s18 = "ction f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){retur" ascii
    $s19 = "0(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\"" ascii
    $s20 = "),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}