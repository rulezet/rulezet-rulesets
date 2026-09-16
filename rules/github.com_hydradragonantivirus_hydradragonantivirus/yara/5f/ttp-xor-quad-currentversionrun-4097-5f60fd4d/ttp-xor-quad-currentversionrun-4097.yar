rule TTP_XOR_QUAD_CurrentVersionRun_4097 {
  strings:
    $key_4097 = { 13 f8 [2] 37 f6 [2] 1c da [2] 32 f8 [2] 26 e3 [2] 29 f9 [2] 37 e4 [2] 35 e5 [2] 2e e3 [2] 32 e4 [2] 2e cb }

  condition:
    any of them
}