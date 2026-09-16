rule TTP_XOR_QUAD_CurrentVersionRun_3088 {
  strings:
    $key_3088 = { 63 e7 [2] 47 e9 [2] 6c c5 [2] 42 e7 [2] 56 fc [2] 59 e6 [2] 47 fb [2] 45 fa [2] 5e fc [2] 42 fb [2] 5e d4 }

  condition:
    any of them
}