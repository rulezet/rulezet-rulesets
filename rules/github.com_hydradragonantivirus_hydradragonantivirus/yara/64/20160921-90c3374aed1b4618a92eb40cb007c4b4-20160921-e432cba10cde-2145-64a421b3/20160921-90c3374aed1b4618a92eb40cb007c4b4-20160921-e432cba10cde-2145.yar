rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_e432cba10cde_2145 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = " f000(){return \"Vj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GG" ascii
    $s2 = "m\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3 = ",(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii
    $s4 = "f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GG" ascii
    $s5 = "eturn \"ZGq\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})()" ascii
    $s6 = "f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GG" ascii
    $s7 = "nction f000(){return \"Fs\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s8 = "),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s9 = "0(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}