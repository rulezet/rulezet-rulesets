rule TTP_XOR_QUAD_CurrentVersionRun_a612 {
  strings:
    $key_a612 = { f5 7d [2] d1 73 [2] fa 5f [2] d4 7d [2] c0 66 [2] cf 7c [2] d1 61 [2] d3 60 [2] c8 66 [2] d4 61 [2] c8 4e }

  condition:
    any of them
}