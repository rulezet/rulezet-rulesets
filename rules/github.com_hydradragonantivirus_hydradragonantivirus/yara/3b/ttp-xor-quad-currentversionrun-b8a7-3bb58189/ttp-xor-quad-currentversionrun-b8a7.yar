rule TTP_XOR_QUAD_CurrentVersionRun_b8a7 {
  strings:
    $key_b8a7 = { eb c8 [2] cf c6 [2] e4 ea [2] ca c8 [2] de d3 [2] d1 c9 [2] cf d4 [2] cd d5 [2] d6 d3 [2] ca d4 [2] d6 fb }

  condition:
    any of them
}