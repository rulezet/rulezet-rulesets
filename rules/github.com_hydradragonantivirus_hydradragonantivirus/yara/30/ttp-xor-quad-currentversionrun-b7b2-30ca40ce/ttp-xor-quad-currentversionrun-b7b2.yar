rule TTP_XOR_QUAD_CurrentVersionRun_b7b2 {
  strings:
    $key_b7b2 = { e4 dd [2] c0 d3 [2] eb ff [2] c5 dd [2] d1 c6 [2] de dc [2] c0 c1 [2] c2 c0 [2] d9 c6 [2] c5 c1 [2] d9 ee }

  condition:
    any of them
}