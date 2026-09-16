rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_2c106cc001da_1792 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"

  strings:
    $s1  = "rn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(fu" ascii
    $s2  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){ret" ascii
    $s3  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s4  = "nction fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5  = "Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AJs\";})(),(functi" ascii
    $s6  = "on fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"" ascii
    $s7  = "(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\"" ascii
    $s8  = "unction fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s9  = ",(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){" ascii
    $s10 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Z" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}