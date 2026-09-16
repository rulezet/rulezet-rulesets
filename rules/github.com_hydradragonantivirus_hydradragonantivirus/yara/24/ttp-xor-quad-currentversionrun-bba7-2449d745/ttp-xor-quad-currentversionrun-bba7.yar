rule TTP_XOR_QUAD_CurrentVersionRun_bba7 {
  strings:
    $key_bba7 = { e8 c8 [2] cc c6 [2] e7 ea [2] c9 c8 [2] dd d3 [2] d2 c9 [2] cc d4 [2] ce d5 [2] d5 d3 [2] c9 d4 [2] d5 fb }

  condition:
    any of them
}