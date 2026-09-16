rule TTP_XOR_QUAD_CurrentVersionRun_a132 {
  strings:
    $key_a132 = { f2 5d [2] d6 53 [2] fd 7f [2] d3 5d [2] c7 46 [2] c8 5c [2] d6 41 [2] d4 40 [2] cf 46 [2] d3 41 [2] cf 6e }

  condition:
    any of them
}