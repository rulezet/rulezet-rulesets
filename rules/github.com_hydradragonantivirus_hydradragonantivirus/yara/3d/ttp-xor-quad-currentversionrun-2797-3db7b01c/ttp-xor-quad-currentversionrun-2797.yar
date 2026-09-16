rule TTP_XOR_QUAD_CurrentVersionRun_2797 {
  strings:
    $key_2797 = { 74 f8 [2] 50 f6 [2] 7b da [2] 55 f8 [2] 41 e3 [2] 4e f9 [2] 50 e4 [2] 52 e5 [2] 49 e3 [2] 55 e4 [2] 49 cb }

  condition:
    any of them
}