rule TTP_XOR_QUAD_CurrentVersionRun_a62e {
  strings:
    $key_a62e = { f5 41 [2] d1 4f [2] fa 63 [2] d4 41 [2] c0 5a [2] cf 40 [2] d1 5d [2] d3 5c [2] c8 5a [2] d4 5d [2] c8 72 }

  condition:
    any of them
}