rule TTP_XOR_QUAD_CurrentVersionRun_f497 {
  strings:
    $key_f497 = { a7 f8 [2] 83 f6 [2] a8 da [2] 86 f8 [2] 92 e3 [2] 9d f9 [2] 83 e4 [2] 81 e5 [2] 9a e3 [2] 86 e4 [2] 9a cb }

  condition:
    any of them
}