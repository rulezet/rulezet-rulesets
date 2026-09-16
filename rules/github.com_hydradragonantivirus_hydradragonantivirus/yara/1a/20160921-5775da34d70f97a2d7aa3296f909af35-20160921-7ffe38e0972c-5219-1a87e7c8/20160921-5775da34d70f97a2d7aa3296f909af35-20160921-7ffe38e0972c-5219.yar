rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_7ffe38e0972c_5219 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"

  strings:
    $s1 = " \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s2 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii
    $s3 = "00(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"PTs" ascii
    $s4 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s5 = "\"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}