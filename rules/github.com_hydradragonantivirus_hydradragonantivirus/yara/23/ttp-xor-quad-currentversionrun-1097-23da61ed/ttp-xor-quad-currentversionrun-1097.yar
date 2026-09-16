rule TTP_XOR_QUAD_CurrentVersionRun_1097 {
  strings:
    $key_1097 = { 43 f8 [2] 67 f6 [2] 4c da [2] 62 f8 [2] 76 e3 [2] 79 f9 [2] 67 e4 [2] 65 e5 [2] 7e e3 [2] 62 e4 [2] 7e cb }

  condition:
    any of them
}