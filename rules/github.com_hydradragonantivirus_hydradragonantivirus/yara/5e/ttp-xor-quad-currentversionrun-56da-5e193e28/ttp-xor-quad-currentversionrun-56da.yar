rule TTP_XOR_QUAD_CurrentVersionRun_56da {
  strings:
    $key_56da = { 05 b5 [2] 21 bb [2] 0a 97 [2] 24 b5 [2] 30 ae [2] 3f b4 [2] 21 a9 [2] 23 a8 [2] 38 ae [2] 24 a9 [2] 38 86 }

  condition:
    any of them
}