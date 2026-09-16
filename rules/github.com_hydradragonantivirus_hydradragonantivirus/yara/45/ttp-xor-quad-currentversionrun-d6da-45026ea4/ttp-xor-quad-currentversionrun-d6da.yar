rule TTP_XOR_QUAD_CurrentVersionRun_d6da {
  strings:
    $key_d6da = { 85 b5 [2] a1 bb [2] 8a 97 [2] a4 b5 [2] b0 ae [2] bf b4 [2] a1 a9 [2] a3 a8 [2] b8 ae [2] a4 a9 [2] b8 86 }

  condition:
    any of them
}