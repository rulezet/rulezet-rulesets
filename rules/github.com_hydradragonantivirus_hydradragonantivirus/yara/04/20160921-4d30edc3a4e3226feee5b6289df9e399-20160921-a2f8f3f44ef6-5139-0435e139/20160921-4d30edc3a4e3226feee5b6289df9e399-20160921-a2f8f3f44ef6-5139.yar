rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_a2f8f3f44ef6_5139 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"

  strings:
    $s1 = "rn \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s2 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s3 = "(),(function fuck(){return \"Et\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s4 = ",(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){r" ascii
    $s5 = "urn \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}