rule TTP_XOR_QUAD_CurrentVersionRun_a1c5 {
  strings:
    $key_a1c5 = { f2 aa [2] d6 a4 [2] fd 88 [2] d3 aa [2] c7 b1 [2] c8 ab [2] d6 b6 [2] d4 b7 [2] cf b1 [2] d3 b6 [2] cf 99 }

  condition:
    any of them
}