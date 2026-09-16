rule TTP_XOR_QUAD_CurrentVersionRun_c4da {
  strings:
    $key_c4da = { 97 b5 [2] b3 bb [2] 98 97 [2] b6 b5 [2] a2 ae [2] ad b4 [2] b3 a9 [2] b1 a8 [2] aa ae [2] b6 a9 [2] aa 86 }

  condition:
    any of them
}