rule TTP_XOR_QUAD_CurrentVersionRun_a663 {
  strings:
    $key_a663 = { f5 0c [2] d1 02 [2] fa 2e [2] d4 0c [2] c0 17 [2] cf 0d [2] d1 10 [2] d3 11 [2] c8 17 [2] d4 10 [2] c8 3f }

  condition:
    any of them
}