rule TTP_XOR_QUAD_CurrentVersionRun_a645 {
  strings:
    $key_a645 = { f5 2a [2] d1 24 [2] fa 08 [2] d4 2a [2] c0 31 [2] cf 2b [2] d1 36 [2] d3 37 [2] c8 31 [2] d4 36 [2] c8 19 }

  condition:
    any of them
}