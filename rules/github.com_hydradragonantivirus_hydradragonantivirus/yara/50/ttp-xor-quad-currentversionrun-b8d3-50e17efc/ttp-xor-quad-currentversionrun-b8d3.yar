rule TTP_XOR_QUAD_CurrentVersionRun_b8d3 {
  strings:
    $key_b8d3 = { eb bc [2] cf b2 [2] e4 9e [2] ca bc [2] de a7 [2] d1 bd [2] cf a0 [2] cd a1 [2] d6 a7 [2] ca a0 [2] d6 8f }

  condition:
    any of them
}