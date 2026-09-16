rule TTP_XOR_QUAD_CurrentVersionRun_39a7 {
  strings:
    $key_39a7 = { 6a c8 [2] 4e c6 [2] 65 ea [2] 4b c8 [2] 5f d3 [2] 50 c9 [2] 4e d4 [2] 4c d5 [2] 57 d3 [2] 4b d4 [2] 57 fb }

  condition:
    any of them
}