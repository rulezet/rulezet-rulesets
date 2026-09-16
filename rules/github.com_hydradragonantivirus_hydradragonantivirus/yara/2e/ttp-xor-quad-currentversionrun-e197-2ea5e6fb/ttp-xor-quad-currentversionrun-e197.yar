rule TTP_XOR_QUAD_CurrentVersionRun_e197 {
  strings:
    $key_e197 = { b2 f8 [2] 96 f6 [2] bd da [2] 93 f8 [2] 87 e3 [2] 88 f9 [2] 96 e4 [2] 94 e5 [2] 8f e3 [2] 93 e4 [2] 8f cb }

  condition:
    any of them
}