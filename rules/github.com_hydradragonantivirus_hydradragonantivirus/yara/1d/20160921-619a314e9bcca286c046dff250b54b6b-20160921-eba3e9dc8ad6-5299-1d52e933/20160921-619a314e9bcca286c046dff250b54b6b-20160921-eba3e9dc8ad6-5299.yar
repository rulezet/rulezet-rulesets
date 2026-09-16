rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_eba3e9dc8ad6_5299 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "ction f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s2 = "function f000(){return \"BMj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s3 = "\"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4 = "ction f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s5 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}