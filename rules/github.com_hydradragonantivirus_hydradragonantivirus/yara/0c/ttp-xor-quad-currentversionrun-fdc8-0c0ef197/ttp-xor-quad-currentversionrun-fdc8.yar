rule TTP_XOR_QUAD_CurrentVersionRun_fdc8 {
  strings:
    $key_fdc8 = { ae a7 [2] 8a a9 [2] a1 85 [2] 8f a7 [2] 9b bc [2] 94 a6 [2] 8a bb [2] 88 ba [2] 93 bc [2] 8f bb [2] 93 94 }

  condition:
    any of them
}