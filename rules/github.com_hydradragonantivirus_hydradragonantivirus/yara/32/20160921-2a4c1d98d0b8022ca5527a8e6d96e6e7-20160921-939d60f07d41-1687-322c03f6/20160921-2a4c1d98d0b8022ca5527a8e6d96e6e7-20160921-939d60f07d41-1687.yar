rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_939d60f07d41_1687 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1  = "\"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s2  = "0(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s3  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000" ascii
    $s4  = "nction f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s5  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(fu" ascii
    $s6  = "(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){r" ascii
    $s7  = " \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s8  = "urn \"PTs\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s9  = "f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu" ascii
    $s10 = "ion f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s11 = ";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}