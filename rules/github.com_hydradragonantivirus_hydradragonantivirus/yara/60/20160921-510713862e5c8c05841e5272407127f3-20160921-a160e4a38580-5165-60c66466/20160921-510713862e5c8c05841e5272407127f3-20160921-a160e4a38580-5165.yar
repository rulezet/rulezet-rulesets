rule _20160921_510713862e5c8c05841e5272407127f3_20160921_a160e4a38580_5165 {
  meta:
    description = "datamaliciousorder - from files 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash2       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash3       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"
    hash4       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "eturn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s2 = "urn \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s3 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = "eturn \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}