rule TTP_XOR_QUAD_CurrentVersionRun_a650 {
  strings:
    $key_a650 = { f5 3f [2] d1 31 [2] fa 1d [2] d4 3f [2] c0 24 [2] cf 3e [2] d1 23 [2] d3 22 [2] c8 24 [2] d4 23 [2] c8 0c }

  condition:
    any of them
}