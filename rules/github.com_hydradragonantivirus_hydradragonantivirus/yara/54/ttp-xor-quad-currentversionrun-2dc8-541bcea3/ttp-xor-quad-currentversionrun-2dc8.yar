rule TTP_XOR_QUAD_CurrentVersionRun_2dc8 {
  strings:
    $key_2dc8 = { 7e a7 [2] 5a a9 [2] 71 85 [2] 5f a7 [2] 4b bc [2] 44 a6 [2] 5a bb [2] 58 ba [2] 43 bc [2] 5f bb [2] 43 94 }

  condition:
    any of them
}