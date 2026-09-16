rule _20160921_531eaafa1b0a00d86f2203fbd289dd63_20160921_6db2cb585eb9_3777 {
  meta:
    description = "datamaliciousorder - from files 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash3       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "n fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s2 = "(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "rn \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s4 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc" ascii
    $s5 = "rn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s6 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}