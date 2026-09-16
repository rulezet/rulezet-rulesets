rule TTP_XOR_QUAD_CurrentVersionRun_a14d {
  strings:
    $key_a14d = { f2 22 [2] d6 2c [2] fd 00 [2] d3 22 [2] c7 39 [2] c8 23 [2] d6 3e [2] d4 3f [2] cf 39 [2] d3 3e [2] cf 11 }

  condition:
    any of them
}