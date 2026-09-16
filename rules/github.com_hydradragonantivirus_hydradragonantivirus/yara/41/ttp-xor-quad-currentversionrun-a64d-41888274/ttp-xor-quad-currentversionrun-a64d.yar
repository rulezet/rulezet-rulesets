rule TTP_XOR_QUAD_CurrentVersionRun_a64d {
  strings:
    $key_a64d = { f5 22 [2] d1 2c [2] fa 00 [2] d4 22 [2] c0 39 [2] cf 23 [2] d1 3e [2] d3 3f [2] c8 39 [2] d4 3e [2] c8 11 }

  condition:
    any of them
}