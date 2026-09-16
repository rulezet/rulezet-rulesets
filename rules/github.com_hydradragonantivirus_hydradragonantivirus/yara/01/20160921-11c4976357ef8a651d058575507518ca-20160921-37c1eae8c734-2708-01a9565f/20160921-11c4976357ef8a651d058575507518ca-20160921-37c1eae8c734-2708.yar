rule _20160921_11c4976357ef8a651d058575507518ca_20160921_37c1eae8c734_2708 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"

  strings:
    $s1 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"KVh\";})(),(function fuck()" ascii
    $s2 = "(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck" ascii
    $s3 = "uck(){return \"Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\"" ascii
    $s4 = "turn \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s5 = " fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"" ascii
    $s6 = "n \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"CCb\";})(),(fun" ascii
    $s7 = "eturn \"Zy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}