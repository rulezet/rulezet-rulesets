rule _20160921_c694815b18c140f34c0f79f86106d901_20160921_fa18251c4ecf_5682 {
  meta:
    description = "datamaliciousorder - from files 20160921_c694815b18c140f34c0f79f86106d901.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"
    hash2       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "ck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\"" ascii
    $s2 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s3 = "unction fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){re" ascii
    $s4 = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jg\";})(),(function fuc" ascii
    $s5 = "urn \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}