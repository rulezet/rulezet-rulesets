rule TTP_XOR_QUAD_CurrentVersionRun_32da {
  strings:
    $key_32da = { 61 b5 [2] 45 bb [2] 6e 97 [2] 40 b5 [2] 54 ae [2] 5b b4 [2] 45 a9 [2] 47 a8 [2] 5c ae [2] 40 a9 [2] 5c 86 }

  condition:
    any of them
}