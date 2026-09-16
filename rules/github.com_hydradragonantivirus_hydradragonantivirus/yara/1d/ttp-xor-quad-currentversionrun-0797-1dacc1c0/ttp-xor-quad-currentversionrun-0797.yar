rule TTP_XOR_QUAD_CurrentVersionRun_0797 {
  strings:
    $key_0797 = { 54 f8 [2] 70 f6 [2] 5b da [2] 75 f8 [2] 61 e3 [2] 6e f9 [2] 70 e4 [2] 72 e5 [2] 69 e3 [2] 75 e4 [2] 69 cb }

  condition:
    any of them
}