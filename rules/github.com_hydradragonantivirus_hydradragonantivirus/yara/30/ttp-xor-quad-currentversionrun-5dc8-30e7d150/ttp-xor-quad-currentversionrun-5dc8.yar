rule TTP_XOR_QUAD_CurrentVersionRun_5dc8 {
  strings:
    $key_5dc8 = { 0e a7 [2] 2a a9 [2] 01 85 [2] 2f a7 [2] 3b bc [2] 34 a6 [2] 2a bb [2] 28 ba [2] 33 bc [2] 2f bb [2] 33 94 }

  condition:
    any of them
}