rule TTP_XOR_QUAD_CurrentVersionRun_e2b3 {
  strings:
    $key_e2b3 = { b1 dc [2] 95 d2 [2] be fe [2] 90 dc [2] 84 c7 [2] 8b dd [2] 95 c0 [2] 97 c1 [2] 8c c7 [2] 90 c0 [2] 8c ef }

  condition:
    any of them
}