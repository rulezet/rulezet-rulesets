rule TTP_XOR_QUAD_CurrentVersionRun_a133 {
  strings:
    $key_a133 = { f2 5c [2] d6 52 [2] fd 7e [2] d3 5c [2] c7 47 [2] c8 5d [2] d6 40 [2] d4 41 [2] cf 47 [2] d3 40 [2] cf 6f }

  condition:
    any of them
}