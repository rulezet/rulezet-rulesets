rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_b71168af39c5_3834 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"

  strings:
    $s1 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(fu" ascii
    $s2 = "return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})()," ascii
    $s3 = "{return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sq\";})()" ascii
    $s4 = "n f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s5 = "rn \"SEo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s6 = "o\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}