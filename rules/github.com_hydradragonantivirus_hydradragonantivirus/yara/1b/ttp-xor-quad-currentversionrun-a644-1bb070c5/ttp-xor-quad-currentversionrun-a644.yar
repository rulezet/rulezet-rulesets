rule TTP_XOR_QUAD_CurrentVersionRun_a644 {
  strings:
    $key_a644 = { f5 2b [2] d1 25 [2] fa 09 [2] d4 2b [2] c0 30 [2] cf 2a [2] d1 37 [2] d3 36 [2] c8 30 [2] d4 37 [2] c8 18 }

  condition:
    any of them
}