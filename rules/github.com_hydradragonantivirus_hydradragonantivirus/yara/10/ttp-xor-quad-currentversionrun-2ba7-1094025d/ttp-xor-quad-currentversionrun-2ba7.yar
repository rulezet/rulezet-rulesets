rule TTP_XOR_QUAD_CurrentVersionRun_2ba7 {
  strings:
    $key_2ba7 = { 78 c8 [2] 5c c6 [2] 77 ea [2] 59 c8 [2] 4d d3 [2] 42 c9 [2] 5c d4 [2] 5e d5 [2] 45 d3 [2] 59 d4 [2] 45 fb }

  condition:
    any of them
}