rule TTP_XOR_QUAD_CurrentVersionRun_e097 {
  strings:
    $key_e097 = { b3 f8 [2] 97 f6 [2] bc da [2] 92 f8 [2] 86 e3 [2] 89 f9 [2] 97 e4 [2] 95 e5 [2] 8e e3 [2] 92 e4 [2] 8e cb }

  condition:
    any of them
}