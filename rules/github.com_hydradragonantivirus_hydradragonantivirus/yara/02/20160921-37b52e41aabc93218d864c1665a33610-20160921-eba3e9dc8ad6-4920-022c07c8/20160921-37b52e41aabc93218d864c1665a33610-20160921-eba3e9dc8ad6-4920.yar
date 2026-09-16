rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_eba3e9dc8ad6_4920 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "){return \"Yv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})" ascii
    $s2 = "function f000(){return \"Qa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s3 = "urn \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(fun" ascii
    $s4 = "ction f000(){return \"KDh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s5 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}