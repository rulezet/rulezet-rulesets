rule TTP_XOR_QUAD_CurrentVersionRun_4ca7 {
  strings:
    $key_4ca7 = { 1f c8 [2] 3b c6 [2] 10 ea [2] 3e c8 [2] 2a d3 [2] 25 c9 [2] 3b d4 [2] 39 d5 [2] 22 d3 [2] 3e d4 [2] 22 fb }

  condition:
    any of them
}