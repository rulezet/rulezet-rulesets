rule _20160921_46b3ab412369507850a916abad1e6bf0_20160921_dff46b67b973_190 {
  meta:
    description = "datamaliciousorder - from files 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){retu" ascii
    $s2  = "function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii
    $s3  = "ion f000(){return \"Nv\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii
    $s4  = " \"Sv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s5  = "tion f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii
    $s6  = " f000(){return \"HJm\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s7  = ";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OMd\";})(),(function f" ascii
    $s8  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb" ascii
    $s9  = "Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Yz\";})(),(function" ascii
    $s10 = "function f000(){return \"DNa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s11 = "000(){return \"Wy\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s12 = "BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s13 = "ction f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s14 = "function f000(){return \"Vu\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){retu" ascii
    $s15 = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s16 = "{return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})()" ascii
    $s17 = "turn \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})()," ascii
    $s18 = "eturn \"DAp\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s19 = "000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Qj" ascii
    $s20 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}