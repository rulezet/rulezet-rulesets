rule TTP_XOR_QUAD_CurrentVersionRun_a6f9 {
  strings:
    $key_a6f9 = { f5 96 [2] d1 98 [2] fa b4 [2] d4 96 [2] c0 8d [2] cf 97 [2] d1 8a [2] d3 8b [2] c8 8d [2] d4 8a [2] c8 a5 }

  condition:
    any of them
}