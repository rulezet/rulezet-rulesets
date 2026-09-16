rule TTP_XOR_QUAD_CurrentVersionRun_3dc8 {
  strings:
    $key_3dc8 = { 6e a7 [2] 4a a9 [2] 61 85 [2] 4f a7 [2] 5b bc [2] 54 a6 [2] 4a bb [2] 48 ba [2] 53 bc [2] 4f bb [2] 53 94 }

  condition:
    any of them
}