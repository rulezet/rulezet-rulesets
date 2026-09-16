rule TTP_XOR_QUAD_CurrentVersionRun_fea7 {
  strings:
    $key_fea7 = { ad c8 [2] 89 c6 [2] a2 ea [2] 8c c8 [2] 98 d3 [2] 97 c9 [2] 89 d4 [2] 8b d5 [2] 90 d3 [2] 8c d4 [2] 90 fb }

  condition:
    any of them
}