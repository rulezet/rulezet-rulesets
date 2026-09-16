rule TTP_XOR_QUAD_CurrentVersionRun_f094 {
  strings:
    $key_f094 = { a3 fb [2] 87 f5 [2] ac d9 [2] 82 fb [2] 96 e0 [2] 99 fa [2] 87 e7 [2] 85 e6 [2] 9e e0 [2] 82 e7 [2] 9e c8 }

  condition:
    any of them
}