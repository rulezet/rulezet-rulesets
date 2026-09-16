rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_afb633ee817d_3891 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1 = "eturn \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(f" ascii
    $s2 = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"Xw\";" ascii
    $s3 = "fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve" ascii
    $s4 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){retu" ascii
    $s5 = "tion fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s6 = "r\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}