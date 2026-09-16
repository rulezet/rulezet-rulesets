rule TTP_XOR_QUAD_CurrentVersionRun_5088 {
  strings:
    $key_5088 = { 03 e7 [2] 27 e9 [2] 0c c5 [2] 22 e7 [2] 36 fc [2] 39 e6 [2] 27 fb [2] 25 fa [2] 3e fc [2] 22 fb [2] 3e d4 }

  condition:
    any of them
}