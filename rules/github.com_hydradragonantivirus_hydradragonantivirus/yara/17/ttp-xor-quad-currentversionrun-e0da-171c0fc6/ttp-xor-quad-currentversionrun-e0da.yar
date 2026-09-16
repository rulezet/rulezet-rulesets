rule TTP_XOR_QUAD_CurrentVersionRun_e0da {
  strings:
    $key_e0da = { b3 b5 [2] 97 bb [2] bc 97 [2] 92 b5 [2] 86 ae [2] 89 b4 [2] 97 a9 [2] 95 a8 [2] 8e ae [2] 92 a9 [2] 8e 86 }

  condition:
    any of them
}