rule TTP_XOR_QUAD_CurrentVersionRun_a7c0 {
  strings:
    $key_a7c0 = { f4 af [2] d0 a1 [2] fb 8d [2] d5 af [2] c1 b4 [2] ce ae [2] d0 b3 [2] d2 b2 [2] c9 b4 [2] d5 b3 [2] c9 9c }

  condition:
    any of them
}