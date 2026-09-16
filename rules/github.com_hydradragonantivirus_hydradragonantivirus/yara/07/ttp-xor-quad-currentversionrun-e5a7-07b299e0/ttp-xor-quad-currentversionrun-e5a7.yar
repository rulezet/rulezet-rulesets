rule TTP_XOR_QUAD_CurrentVersionRun_e5a7 {
  strings:
    $key_e5a7 = { b6 c8 [2] 92 c6 [2] b9 ea [2] 97 c8 [2] 83 d3 [2] 8c c9 [2] 92 d4 [2] 90 d5 [2] 8b d3 [2] 97 d4 [2] 8b fb }

  condition:
    any of them
}