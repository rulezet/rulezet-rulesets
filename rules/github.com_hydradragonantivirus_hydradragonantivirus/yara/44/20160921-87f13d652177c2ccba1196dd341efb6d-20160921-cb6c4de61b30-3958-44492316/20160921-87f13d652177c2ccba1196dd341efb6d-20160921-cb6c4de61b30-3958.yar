rule _20160921_87f13d652177c2ccba1196dd341efb6d_20160921_cb6c4de61b30_3958 {
  meta:
    description = "datamaliciousorder - from files 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "eturn \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(" ascii
    $s2 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){r" ascii
    $s4 = "return \"Rh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s6 = "return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}