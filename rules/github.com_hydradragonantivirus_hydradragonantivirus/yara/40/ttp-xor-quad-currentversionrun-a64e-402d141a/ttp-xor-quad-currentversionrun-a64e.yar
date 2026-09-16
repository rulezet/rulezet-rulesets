rule TTP_XOR_QUAD_CurrentVersionRun_a64e {
  strings:
    $key_a64e = { f5 21 [2] d1 2f [2] fa 03 [2] d4 21 [2] c0 3a [2] cf 20 [2] d1 3d [2] d3 3c [2] c8 3a [2] d4 3d [2] c8 12 }

  condition:
    any of them
}