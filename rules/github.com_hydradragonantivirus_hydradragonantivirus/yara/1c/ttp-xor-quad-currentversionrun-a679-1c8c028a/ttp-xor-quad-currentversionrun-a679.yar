rule TTP_XOR_QUAD_CurrentVersionRun_a679 {
  strings:
    $key_a679 = { f5 16 [2] d1 18 [2] fa 34 [2] d4 16 [2] c0 0d [2] cf 17 [2] d1 0a [2] d3 0b [2] c8 0d [2] d4 0a [2] c8 25 }

  condition:
    any of them
}