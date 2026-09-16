rule TTP_XOR_QUAD_CurrentVersionRun_f3a8 {
  strings:
    $key_f3a8 = { a0 c7 [2] 84 c9 [2] af e5 [2] 81 c7 [2] 95 dc [2] 9a c6 [2] 84 db [2] 86 da [2] 9d dc [2] 81 db [2] 9d f4 }

  condition:
    any of them
}