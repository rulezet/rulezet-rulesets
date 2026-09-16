rule TTP_XOR_QUAD_CurrentVersionRun_a6c1 {
  strings:
    $key_a6c1 = { f5 ae [2] d1 a0 [2] fa 8c [2] d4 ae [2] c0 b5 [2] cf af [2] d1 b2 [2] d3 b3 [2] c8 b5 [2] d4 b2 [2] c8 9d }

  condition:
    any of them
}