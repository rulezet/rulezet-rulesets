rule TTP_XOR_QUAD_CurrentVersionRun_e8c8 {
  strings:
    $key_e8c8 = { bb a7 [2] 9f a9 [2] b4 85 [2] 9a a7 [2] 8e bc [2] 81 a6 [2] 9f bb [2] 9d ba [2] 86 bc [2] 9a bb [2] 86 94 }

  condition:
    any of them
}