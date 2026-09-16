rule TTP_XOR_QUAD_CurrentVersionRun_b6da {
  strings:
    $key_b6da = { e5 b5 [2] c1 bb [2] ea 97 [2] c4 b5 [2] d0 ae [2] df b4 [2] c1 a9 [2] c3 a8 [2] d8 ae [2] c4 a9 [2] d8 86 }

  condition:
    any of them
}