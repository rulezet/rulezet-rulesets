rule TTP_XOR_QUAD_CurrentVersionRun_a126 {
  strings:
    $key_a126 = { f2 49 [2] d6 47 [2] fd 6b [2] d3 49 [2] c7 52 [2] c8 48 [2] d6 55 [2] d4 54 [2] cf 52 [2] d3 55 [2] cf 7a }

  condition:
    any of them
}