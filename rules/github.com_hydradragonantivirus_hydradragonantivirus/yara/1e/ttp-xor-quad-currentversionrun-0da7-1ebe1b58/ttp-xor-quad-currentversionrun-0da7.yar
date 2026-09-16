rule TTP_XOR_QUAD_CurrentVersionRun_0da7 {
  strings:
    $key_0da7 = { 5e c8 [2] 7a c6 [2] 51 ea [2] 7f c8 [2] 6b d3 [2] 64 c9 [2] 7a d4 [2] 78 d5 [2] 63 d3 [2] 7f d4 [2] 63 fb }

  condition:
    any of them
}