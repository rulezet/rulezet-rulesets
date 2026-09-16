rule TTP_XOR_QUAD_CurrentVersionRun_e7b4 {
  strings:
    $key_e7b4 = { b4 db [2] 90 d5 [2] bb f9 [2] 95 db [2] 81 c0 [2] 8e da [2] 90 c7 [2] 92 c6 [2] 89 c0 [2] 95 c7 [2] 89 e8 }

  condition:
    any of them
}