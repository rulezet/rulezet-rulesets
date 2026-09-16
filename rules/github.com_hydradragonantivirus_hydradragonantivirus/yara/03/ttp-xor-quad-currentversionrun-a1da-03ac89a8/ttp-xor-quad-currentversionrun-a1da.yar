rule TTP_XOR_QUAD_CurrentVersionRun_a1da {
  strings:
    $key_a1da = { f2 b5 [2] d6 bb [2] fd 97 [2] d3 b5 [2] c7 ae [2] c8 b4 [2] d6 a9 [2] d4 a8 [2] cf ae [2] d3 a9 [2] cf 86 }

  condition:
    any of them
}