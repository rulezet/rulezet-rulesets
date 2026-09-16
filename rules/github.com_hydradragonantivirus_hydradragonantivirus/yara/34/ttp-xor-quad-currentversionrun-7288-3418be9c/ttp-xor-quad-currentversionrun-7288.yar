rule TTP_XOR_QUAD_CurrentVersionRun_7288 {
  strings:
    $key_7288 = { 21 e7 [2] 05 e9 [2] 2e c5 [2] 00 e7 [2] 14 fc [2] 1b e6 [2] 05 fb [2] 07 fa [2] 1c fc [2] 00 fb [2] 1c d4 }

  condition:
    any of them
}