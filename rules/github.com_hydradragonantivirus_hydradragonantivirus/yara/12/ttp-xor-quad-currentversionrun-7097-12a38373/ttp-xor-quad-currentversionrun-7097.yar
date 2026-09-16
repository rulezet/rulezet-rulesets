rule TTP_XOR_QUAD_CurrentVersionRun_7097 {
  strings:
    $key_7097 = { 23 f8 [2] 07 f6 [2] 2c da [2] 02 f8 [2] 16 e3 [2] 19 f9 [2] 07 e4 [2] 05 e5 [2] 1e e3 [2] 02 e4 [2] 1e cb }

  condition:
    any of them
}