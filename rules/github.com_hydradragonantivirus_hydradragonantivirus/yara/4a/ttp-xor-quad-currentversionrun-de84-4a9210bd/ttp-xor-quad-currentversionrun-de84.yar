rule TTP_XOR_QUAD_CurrentVersionRun_de84 {
  strings:
    $key_de84 = { 8d eb [2] a9 e5 [2] 82 c9 [2] ac eb [2] b8 f0 [2] b7 ea [2] a9 f7 [2] ab f6 [2] b0 f0 [2] ac f7 [2] b0 d8 }

  condition:
    any of them
}