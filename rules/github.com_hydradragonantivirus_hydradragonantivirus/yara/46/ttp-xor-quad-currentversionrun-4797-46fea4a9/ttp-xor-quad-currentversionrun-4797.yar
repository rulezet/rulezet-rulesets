rule TTP_XOR_QUAD_CurrentVersionRun_4797 {
  strings:
    $key_4797 = { 14 f8 [2] 30 f6 [2] 1b da [2] 35 f8 [2] 21 e3 [2] 2e f9 [2] 30 e4 [2] 32 e5 [2] 29 e3 [2] 35 e4 [2] 29 cb }

  condition:
    any of them
}