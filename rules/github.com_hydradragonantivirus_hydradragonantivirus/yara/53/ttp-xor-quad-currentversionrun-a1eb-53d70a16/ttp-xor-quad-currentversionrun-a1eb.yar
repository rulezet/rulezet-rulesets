rule TTP_XOR_QUAD_CurrentVersionRun_a1eb {
  strings:
    $key_a1eb = { f2 84 [2] d6 8a [2] fd a6 [2] d3 84 [2] c7 9f [2] c8 85 [2] d6 98 [2] d4 99 [2] cf 9f [2] d3 98 [2] cf b7 }

  condition:
    any of them
}