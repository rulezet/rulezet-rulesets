rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_5f5611940db7_4276 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s2 = " \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(func" ascii
    $s3 = "\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function " ascii
    $s4 = "Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(functio" ascii
    $s5 = "urn \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}