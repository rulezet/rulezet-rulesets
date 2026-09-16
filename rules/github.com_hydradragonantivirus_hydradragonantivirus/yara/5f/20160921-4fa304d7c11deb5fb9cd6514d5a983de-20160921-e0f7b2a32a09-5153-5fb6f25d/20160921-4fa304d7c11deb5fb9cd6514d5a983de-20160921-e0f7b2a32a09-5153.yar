rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_e0f7b2a32a09_5153 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2 = "fuck(){return \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s3 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s4 = ",(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){r" ascii
    $s5 = "k(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}