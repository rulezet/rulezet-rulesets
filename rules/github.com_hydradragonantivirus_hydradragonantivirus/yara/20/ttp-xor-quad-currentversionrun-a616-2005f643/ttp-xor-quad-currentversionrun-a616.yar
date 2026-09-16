rule TTP_XOR_QUAD_CurrentVersionRun_a616 {
  strings:
    $key_a616 = { f5 79 [2] d1 77 [2] fa 5b [2] d4 79 [2] c0 62 [2] cf 78 [2] d1 65 [2] d3 64 [2] c8 62 [2] d4 65 [2] c8 4a }

  condition:
    any of them
}