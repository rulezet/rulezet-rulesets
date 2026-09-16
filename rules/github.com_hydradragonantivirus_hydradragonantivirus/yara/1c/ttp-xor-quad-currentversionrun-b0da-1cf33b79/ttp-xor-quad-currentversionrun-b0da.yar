rule TTP_XOR_QUAD_CurrentVersionRun_b0da {
  strings:
    $key_b0da = { e3 b5 [2] c7 bb [2] ec 97 [2] c2 b5 [2] d6 ae [2] d9 b4 [2] c7 a9 [2] c5 a8 [2] de ae [2] c2 a9 [2] de 86 }

  condition:
    any of them
}