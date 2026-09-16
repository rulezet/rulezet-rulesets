rule TTP_XOR_QUAD_CurrentVersionRun_a666 {
  strings:
    $key_a666 = { f5 09 [2] d1 07 [2] fa 2b [2] d4 09 [2] c0 12 [2] cf 08 [2] d1 15 [2] d3 14 [2] c8 12 [2] d4 15 [2] c8 3a }

  condition:
    any of them
}