rule TTP_XOR_QUAD_CurrentVersionRun_f088 {
  strings:
    $key_f088 = { a3 e7 [2] 87 e9 [2] ac c5 [2] 82 e7 [2] 96 fc [2] 99 e6 [2] 87 fb [2] 85 fa [2] 9e fc [2] 82 fb [2] 9e d4 }

  condition:
    any of them
}