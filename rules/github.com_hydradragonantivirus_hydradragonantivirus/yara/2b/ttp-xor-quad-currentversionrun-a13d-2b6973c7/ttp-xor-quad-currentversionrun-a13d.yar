rule TTP_XOR_QUAD_CurrentVersionRun_a13d {
  strings:
    $key_a13d = { f2 52 [2] d6 5c [2] fd 70 [2] d3 52 [2] c7 49 [2] c8 53 [2] d6 4e [2] d4 4f [2] cf 49 [2] d3 4e [2] cf 61 }

  condition:
    any of them
}