rule _20160921_c1b40d45f00b78160e529a681e4a3e74_20160921_ccabe4fce99c_3139 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"

  strings:
    $s1 = "\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s2 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Sq\";})(),(function f000()" ascii
    $s3 = "f000(){return \"Qa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IA" ascii
    $s4 = "turn \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Qa\";})(),(" ascii
    $s5 = " f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"E" ascii
    $s6 = "ction f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){retu" ascii
    $s7 = ",(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}