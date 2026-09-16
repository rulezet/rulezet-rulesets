rule TTP_XOR_QUAD_CurrentVersionRun_f488 {
  strings:
    $key_f488 = { a7 e7 [2] 83 e9 [2] a8 c5 [2] 86 e7 [2] 92 fc [2] 9d e6 [2] 83 fb [2] 81 fa [2] 9a fc [2] 86 fb [2] 9a d4 }

  condition:
    any of them
}