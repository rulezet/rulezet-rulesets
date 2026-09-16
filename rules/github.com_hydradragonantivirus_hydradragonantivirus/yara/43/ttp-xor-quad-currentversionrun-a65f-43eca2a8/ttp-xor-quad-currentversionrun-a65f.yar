rule TTP_XOR_QUAD_CurrentVersionRun_a65f {
  strings:
    $key_a65f = { f5 30 [2] d1 3e [2] fa 12 [2] d4 30 [2] c0 2b [2] cf 31 [2] d1 2c [2] d3 2d [2] c8 2b [2] d4 2c [2] c8 03 }

  condition:
    any of them
}