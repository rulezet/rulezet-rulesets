rule _20160921_95c689d7ff4700a03d604b71aaf3634b_20160921_d29f34806a7d_1053 {
  meta:
    description = "datamaliciousorder - from files 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1  = ")(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck()" ascii
    $s2  = "\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii
    $s3  = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"GJx\";})(),(function " ascii
    $s4  = "rn \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"SUi\";})(),(fu" ascii
    $s5  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){ret" ascii
    $s6  = ")(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii
    $s7  = "eturn \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s8  = "{return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";}" ascii
    $s9  = "on fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s10 = "uck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Mw" ascii
    $s11 = "ck(){return \"Nm\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";" ascii
    $s12 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){retu" ascii
    $s13 = " \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s14 = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){ret" ascii
    $s15 = "ck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\"" ascii
    $s16 = "(){return \"MIl\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Hs\";})" ascii
    $s17 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){ret" ascii
    $s18 = "urn \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"SUi\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}