rule TTP_XOR_QUAD_CurrentVersionRun_b5a7 {
  strings:
    $key_b5a7 = { e6 c8 [2] c2 c6 [2] e9 ea [2] c7 c8 [2] d3 d3 [2] dc c9 [2] c2 d4 [2] c0 d5 [2] db d3 [2] c7 d4 [2] db fb }

  condition:
    any of them
}