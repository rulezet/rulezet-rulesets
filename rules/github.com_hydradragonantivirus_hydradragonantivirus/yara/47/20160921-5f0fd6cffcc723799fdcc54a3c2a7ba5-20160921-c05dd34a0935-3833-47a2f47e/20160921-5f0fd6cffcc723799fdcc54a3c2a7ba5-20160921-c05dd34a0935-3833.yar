rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_c05dd34a0935_3833 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1 = "unction f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s2 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(func" ascii
    $s3 = "{return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(" ascii
    $s4 = "0(){return \"UEg\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6 = "){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}