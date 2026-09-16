rule TTP_XOR_QUAD_CurrentVersionRun_a662 {
  strings:
    $key_a662 = { f5 0d [2] d1 03 [2] fa 2f [2] d4 0d [2] c0 16 [2] cf 0c [2] d1 11 [2] d3 10 [2] c8 16 [2] d4 11 [2] c8 3e }

  condition:
    any of them
}