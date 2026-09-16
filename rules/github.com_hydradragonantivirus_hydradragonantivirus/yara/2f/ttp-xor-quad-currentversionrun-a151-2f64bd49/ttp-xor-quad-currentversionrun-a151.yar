rule TTP_XOR_QUAD_CurrentVersionRun_a151 {
  strings:
    $key_a151 = { f2 3e [2] d6 30 [2] fd 1c [2] d3 3e [2] c7 25 [2] c8 3f [2] d6 22 [2] d4 23 [2] cf 25 [2] d3 22 [2] cf 0d }

  condition:
    any of them
}