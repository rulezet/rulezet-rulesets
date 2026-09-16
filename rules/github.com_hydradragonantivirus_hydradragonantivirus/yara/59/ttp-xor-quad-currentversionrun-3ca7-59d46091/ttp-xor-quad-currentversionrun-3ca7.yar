rule TTP_XOR_QUAD_CurrentVersionRun_3ca7 {
  strings:
    $key_3ca7 = { 6f c8 [2] 4b c6 [2] 60 ea [2] 4e c8 [2] 5a d3 [2] 55 c9 [2] 4b d4 [2] 49 d5 [2] 52 d3 [2] 4e d4 [2] 52 fb }

  condition:
    any of them
}