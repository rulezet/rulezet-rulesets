rule TTP_XOR_QUAD_CurrentVersionRun_3097 {
  strings:
    $key_3097 = { 63 f8 [2] 47 f6 [2] 6c da [2] 42 f8 [2] 56 e3 [2] 59 f9 [2] 47 e4 [2] 45 e5 [2] 5e e3 [2] 42 e4 [2] 5e cb }

  condition:
    any of them
}