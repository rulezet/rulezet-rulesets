rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_5775da34d70f_4607 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"

  strings:
    $s1 = " \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s2 = "(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3 = "00(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\"" ascii
    $s4 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s5 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}