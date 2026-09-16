rule TTP_XOR_QUAD_CurrentVersionRun_a6f3 {
  strings:
    $key_a6f3 = { f5 9c [2] d1 92 [2] fa be [2] d4 9c [2] c0 87 [2] cf 9d [2] d1 80 [2] d3 81 [2] c8 87 [2] d4 80 [2] c8 af }

  condition:
    any of them
}