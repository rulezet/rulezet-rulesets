rule TTP_XOR_QUAD_CurrentVersionRun_a65d {
  strings:
    $key_a65d = { f5 32 [2] d1 3c [2] fa 10 [2] d4 32 [2] c0 29 [2] cf 33 [2] d1 2e [2] d3 2f [2] c8 29 [2] d4 2e [2] c8 01 }

  condition:
    any of them
}