rule TTP_XOR_QUAD_CurrentVersionRun_5097 {
  strings:
    $key_5097 = { 03 f8 [2] 27 f6 [2] 0c da [2] 22 f8 [2] 36 e3 [2] 39 f9 [2] 27 e4 [2] 25 e5 [2] 3e e3 [2] 22 e4 [2] 3e cb }

  condition:
    any of them
}