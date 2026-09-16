rule TTP_XOR_QUAD_CurrentVersionRun_0aa7 {
  strings:
    $key_0aa7 = { 59 c8 [2] 7d c6 [2] 56 ea [2] 78 c8 [2] 6c d3 [2] 63 c9 [2] 7d d4 [2] 7f d5 [2] 64 d3 [2] 78 d4 [2] 64 fb }

  condition:
    any of them
}