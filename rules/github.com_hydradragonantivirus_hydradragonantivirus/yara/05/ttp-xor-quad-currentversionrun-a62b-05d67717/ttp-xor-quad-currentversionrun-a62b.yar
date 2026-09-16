rule TTP_XOR_QUAD_CurrentVersionRun_a62b {
  strings:
    $key_a62b = { f5 44 [2] d1 4a [2] fa 66 [2] d4 44 [2] c0 5f [2] cf 45 [2] d1 58 [2] d3 59 [2] c8 5f [2] d4 58 [2] c8 77 }

  condition:
    any of them
}