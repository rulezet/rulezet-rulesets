rule TTP_XOR_QUAD_CurrentVersionRun_a61a {
  strings:
    $key_a61a = { f5 75 [2] d1 7b [2] fa 57 [2] d4 75 [2] c0 6e [2] cf 74 [2] d1 69 [2] d3 68 [2] c8 6e [2] d4 69 [2] c8 46 }

  condition:
    any of them
}