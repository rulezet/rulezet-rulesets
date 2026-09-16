rule TTP_XOR_QUAD_CurrentVersionRun_e7b6 {
  strings:
    $key_e7b6 = { b4 d9 [2] 90 d7 [2] bb fb [2] 95 d9 [2] 81 c2 [2] 8e d8 [2] 90 c5 [2] 92 c4 [2] 89 c2 [2] 95 c5 [2] 89 ea }

  condition:
    any of them
}