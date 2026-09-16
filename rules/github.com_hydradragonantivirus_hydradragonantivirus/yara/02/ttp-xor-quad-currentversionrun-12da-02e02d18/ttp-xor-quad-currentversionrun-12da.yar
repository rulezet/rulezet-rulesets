rule TTP_XOR_QUAD_CurrentVersionRun_12da {
  strings:
    $key_12da = { 41 b5 [2] 65 bb [2] 4e 97 [2] 60 b5 [2] 74 ae [2] 7b b4 [2] 65 a9 [2] 67 a8 [2] 7c ae [2] 60 a9 [2] 7c 86 }

  condition:
    any of them
}