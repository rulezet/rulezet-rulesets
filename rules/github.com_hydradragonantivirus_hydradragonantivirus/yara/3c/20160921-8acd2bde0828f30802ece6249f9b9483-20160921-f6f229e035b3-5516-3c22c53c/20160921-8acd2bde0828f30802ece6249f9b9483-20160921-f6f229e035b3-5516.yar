rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_f6f229e035b3_5516 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s2 = ",(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){r" ascii
    $s3 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s4 = "k(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";" ascii
    $s5 = "nction fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}