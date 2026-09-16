rule _20160921_e0f7b2a32a0967097baa59c67369ba3a_20160921_f2abfe62ed22_5723 {
  meta:
    description = "datamaliciousorder - from files 20160921_e0f7b2a32a0967097baa59c67369ba3a.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"
    hash2       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "uck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MBg" ascii
    $s2 = "n fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"" ascii
    $s3 = " \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s4 = "unction fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retur" ascii
    $s5 = "fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}