rule TTP_XOR_QUAD_CurrentVersionRun_b1da {
  strings:
    $key_b1da = { e2 b5 [2] c6 bb [2] ed 97 [2] c3 b5 [2] d7 ae [2] d8 b4 [2] c6 a9 [2] c4 a8 [2] df ae [2] c3 a9 [2] df 86 }

  condition:
    any of them
}