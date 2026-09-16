rule TTP_XOR_QUAD_CurrentVersionRun_5094 {
  strings:
    $key_5094 = { 03 fb [2] 27 f5 [2] 0c d9 [2] 22 fb [2] 36 e0 [2] 39 fa [2] 27 e7 [2] 25 e6 [2] 3e e0 [2] 22 e7 [2] 3e c8 }

  condition:
    any of them
}