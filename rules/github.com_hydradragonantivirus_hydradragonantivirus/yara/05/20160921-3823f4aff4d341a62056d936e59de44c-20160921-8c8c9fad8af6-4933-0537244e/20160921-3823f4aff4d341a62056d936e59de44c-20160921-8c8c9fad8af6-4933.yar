rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_8c8c9fad8af6_4933 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1 = "n fuck(){return \"Cd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IP" ascii
    $s2 = "n \"Fv\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UXf\"" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Sx\";})(),(function" ascii
    $s5 = "ck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}