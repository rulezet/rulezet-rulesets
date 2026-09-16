rule TTP_XOR_QUAD_CurrentVersionRun_3288 {
  strings:
    $key_3288 = { 61 e7 [2] 45 e9 [2] 6e c5 [2] 40 e7 [2] 54 fc [2] 5b e6 [2] 45 fb [2] 47 fa [2] 5c fc [2] 40 fb [2] 5c d4 }

  condition:
    any of them
}