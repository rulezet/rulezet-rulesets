rule TTP_XOR_QUAD_CurrentVersionRun_a1c2 {
  strings:
    $key_a1c2 = { f2 ad [2] d6 a3 [2] fd 8f [2] d3 ad [2] c7 b6 [2] c8 ac [2] d6 b1 [2] d4 b0 [2] cf b6 [2] d3 b1 [2] cf 9e }

  condition:
    any of them
}