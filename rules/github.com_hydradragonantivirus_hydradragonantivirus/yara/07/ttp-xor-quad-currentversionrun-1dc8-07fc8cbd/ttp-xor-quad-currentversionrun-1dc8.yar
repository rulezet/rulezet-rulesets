rule TTP_XOR_QUAD_CurrentVersionRun_1dc8 {
  strings:
    $key_1dc8 = { 4e a7 [2] 6a a9 [2] 41 85 [2] 6f a7 [2] 7b bc [2] 74 a6 [2] 6a bb [2] 68 ba [2] 73 bc [2] 6f bb [2] 73 94 }

  condition:
    any of them
}