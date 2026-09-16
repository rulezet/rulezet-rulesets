rule TTP_XOR_QUAD_CurrentVersionRun_a64a {
  strings:
    $key_a64a = { f5 25 [2] d1 2b [2] fa 07 [2] d4 25 [2] c0 3e [2] cf 24 [2] d1 39 [2] d3 38 [2] c8 3e [2] d4 39 [2] c8 16 }

  condition:
    any of them
}