rule TTP_XOR_QUAD_CurrentVersionRun_b8b2 {
  strings:
    $key_b8b2 = { eb dd [2] cf d3 [2] e4 ff [2] ca dd [2] de c6 [2] d1 dc [2] cf c1 [2] cd c0 [2] d6 c6 [2] ca c1 [2] d6 ee }

  condition:
    any of them
}