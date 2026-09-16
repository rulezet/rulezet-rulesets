rule TTP_XOR_QUAD_CurrentVersionRun_a669 {
  strings:
    $key_a669 = { f5 06 [2] d1 08 [2] fa 24 [2] d4 06 [2] c0 1d [2] cf 07 [2] d1 1a [2] d3 1b [2] c8 1d [2] d4 1a [2] c8 35 }

  condition:
    any of them
}