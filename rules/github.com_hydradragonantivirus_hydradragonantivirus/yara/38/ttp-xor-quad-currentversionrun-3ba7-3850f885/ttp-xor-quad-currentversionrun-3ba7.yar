rule TTP_XOR_QUAD_CurrentVersionRun_3ba7 {
  strings:
    $key_3ba7 = { 68 c8 [2] 4c c6 [2] 67 ea [2] 49 c8 [2] 5d d3 [2] 52 c9 [2] 4c d4 [2] 4e d5 [2] 55 d3 [2] 49 d4 [2] 55 fb }

  condition:
    any of them
}