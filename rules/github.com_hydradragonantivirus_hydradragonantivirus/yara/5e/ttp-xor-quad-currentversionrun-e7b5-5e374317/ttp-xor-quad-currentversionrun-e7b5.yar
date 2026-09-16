rule TTP_XOR_QUAD_CurrentVersionRun_e7b5 {
  strings:
    $key_e7b5 = { b4 da [2] 90 d4 [2] bb f8 [2] 95 da [2] 81 c1 [2] 8e db [2] 90 c6 [2] 92 c7 [2] 89 c1 [2] 95 c6 [2] 89 e9 }

  condition:
    any of them
}