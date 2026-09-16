rule TTP_XOR_QUAD_CurrentVersionRun_a640 {
  strings:
    $key_a640 = { f5 2f [2] d1 21 [2] fa 0d [2] d4 2f [2] c0 34 [2] cf 2e [2] d1 33 [2] d3 32 [2] c8 34 [2] d4 33 [2] c8 1c }

  condition:
    any of them
}