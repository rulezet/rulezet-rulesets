rule TTP_XOR_QUAD_CurrentVersionRun_a6f1 {
  strings:
    $key_a6f1 = { f5 9e [2] d1 90 [2] fa bc [2] d4 9e [2] c0 85 [2] cf 9f [2] d1 82 [2] d3 83 [2] c8 85 [2] d4 82 [2] c8 ad }

  condition:
    any of them
}