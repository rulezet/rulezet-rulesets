rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_78bd4256ddc0_4434 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "k(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn" ascii
    $s2 = "\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s5 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}