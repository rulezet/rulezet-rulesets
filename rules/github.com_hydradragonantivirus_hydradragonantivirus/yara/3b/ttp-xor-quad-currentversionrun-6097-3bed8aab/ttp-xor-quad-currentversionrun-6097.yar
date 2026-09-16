rule TTP_XOR_QUAD_CurrentVersionRun_6097 {
  strings:
    $key_6097 = { 33 f8 [2] 17 f6 [2] 3c da [2] 12 f8 [2] 06 e3 [2] 09 f9 [2] 17 e4 [2] 15 e5 [2] 0e e3 [2] 12 e4 [2] 0e cb }

  condition:
    any of them
}