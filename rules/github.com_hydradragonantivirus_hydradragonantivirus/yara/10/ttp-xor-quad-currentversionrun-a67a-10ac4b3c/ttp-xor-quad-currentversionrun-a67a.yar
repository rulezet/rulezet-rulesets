rule TTP_XOR_QUAD_CurrentVersionRun_a67a {
  strings:
    $key_a67a = { f5 15 [2] d1 1b [2] fa 37 [2] d4 15 [2] c0 0e [2] cf 14 [2] d1 09 [2] d3 08 [2] c8 0e [2] d4 09 [2] c8 26 }

  condition:
    any of them
}