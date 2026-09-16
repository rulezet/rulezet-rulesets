rule _20160921_882f77897bba85afdc56810c29ef4cbb_20160921_cae1392fd0c6_105 {
  meta:
    description = "datamaliciousorder - from files 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1  = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f" ascii
    $s2  = "unction f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s3  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s4  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTs\";})(),(f" ascii
    $s5  = "{return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"PTi\";})" ascii
    $s6  = "{return \"PTi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})" ascii
    $s7  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"EZu\";})(),(function f00" ascii
    $s8  = "tion f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s9  = "0(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";" ascii
    $s10 = "rn \"Br\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s11 = "turn \"MKa\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sv\";})()," ascii
    $s12 = "(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){" ascii
    $s13 = "rn \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s14 = "(){return \"Qj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(" ascii
    $s15 = "rn \"ZIi\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s16 = " \"NBs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s17 = "return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})()" ascii
    $s18 = "f000(){return \"Wb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s19 = "turn \"Yv\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s20 = "n\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}