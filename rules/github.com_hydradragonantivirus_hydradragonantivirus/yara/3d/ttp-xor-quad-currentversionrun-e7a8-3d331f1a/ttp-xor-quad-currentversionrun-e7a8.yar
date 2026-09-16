rule TTP_XOR_QUAD_CurrentVersionRun_e7a8 {
  strings:
    $key_e7a8 = { b4 c7 [2] 90 c9 [2] bb e5 [2] 95 c7 [2] 81 dc [2] 8e c6 [2] 90 db [2] 92 da [2] 89 dc [2] 95 db [2] 89 f4 }

  condition:
    any of them
}