rule TTP_XOR_QUAD_CurrentVersionRun_c797 {
  strings:
    $key_c797 = { 94 f8 [2] b0 f6 [2] 9b da [2] b5 f8 [2] a1 e3 [2] ae f9 [2] b0 e4 [2] b2 e5 [2] a9 e3 [2] b5 e4 [2] a9 cb }

  condition:
    any of them
}