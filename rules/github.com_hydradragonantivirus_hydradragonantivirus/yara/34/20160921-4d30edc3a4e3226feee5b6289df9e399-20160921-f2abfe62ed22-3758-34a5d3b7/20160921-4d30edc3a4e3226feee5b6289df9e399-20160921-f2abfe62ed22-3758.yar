rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_f2abfe62ed22_3758 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"N" ascii
    $s2 = ")(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s3 = "n \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s4 = "return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5 = "rn \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s6 = "\"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}