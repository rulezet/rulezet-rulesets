rule TTP_XOR_QUAD_CurrentVersionRun_a6ee {
  strings:
    $key_a6ee = { f5 81 [2] d1 8f [2] fa a3 [2] d4 81 [2] c0 9a [2] cf 80 [2] d1 9d [2] d3 9c [2] c8 9a [2] d4 9d [2] c8 b2 }

  condition:
    any of them
}