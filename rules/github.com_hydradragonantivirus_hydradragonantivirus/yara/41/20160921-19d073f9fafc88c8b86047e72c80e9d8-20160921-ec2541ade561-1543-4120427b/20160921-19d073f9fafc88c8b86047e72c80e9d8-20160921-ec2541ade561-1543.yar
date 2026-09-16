rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_ec2541ade561_1543 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1  = "),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s2  = "tion f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s3  = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Z" ascii
    $s4  = "){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RVb\";}" ascii
    $s5  = "turn \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s6  = "eturn \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})()," ascii
    $s7  = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s8  = "n f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"M" ascii
    $s9  = "unction f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s10 = "turn \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s11 = "on f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s12 = "ction f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}