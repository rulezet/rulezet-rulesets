rule TTP_XOR_QUAD_CurrentVersionRun_a6c0 {
  strings:
    $key_a6c0 = { f5 af [2] d1 a1 [2] fa 8d [2] d4 af [2] c0 b4 [2] cf ae [2] d1 b3 [2] d3 b2 [2] c8 b4 [2] d4 b3 [2] c8 9c }

  condition:
    any of them
}