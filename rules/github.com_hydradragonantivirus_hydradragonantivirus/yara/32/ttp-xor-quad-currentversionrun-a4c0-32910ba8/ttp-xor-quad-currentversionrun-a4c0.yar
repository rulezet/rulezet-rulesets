rule TTP_XOR_QUAD_CurrentVersionRun_a4c0 {
  strings:
    $key_a4c0 = { f7 af [2] d3 a1 [2] f8 8d [2] d6 af [2] c2 b4 [2] cd ae [2] d3 b3 [2] d1 b2 [2] ca b4 [2] d6 b3 [2] ca 9c }

  condition:
    any of them
}