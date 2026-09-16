rule _20160921_62f4f68c59540f36d255485f0f0e37c9_20160921_9b04118eed50_1213 {
  meta:
    description = "datamaliciousorder - from files 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash2       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"

  strings:
    $s1  = "nction fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s2  = "eturn \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s3  = "rn \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(fun" ascii
    $s4  = "function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){re" ascii
    $s5  = "function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retu" ascii
    $s6  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return " ascii
    $s7  = "b\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function f" ascii
    $s8  = "n fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"U" ascii
    $s9  = "rn \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(fu" ascii
    $s10 = "n fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s11 = "eturn \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(" ascii
    $s12 = "urn \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s13 = " fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"I" ascii
    $s14 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function" ascii
    $s15 = "ck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\"" ascii
    $s16 = "n fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}