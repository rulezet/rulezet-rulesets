rule TTP_XOR_QUAD_CurrentVersionRun_f2da {
  strings:
    $key_f2da = { a1 b5 [2] 85 bb [2] ae 97 [2] 80 b5 [2] 94 ae [2] 9b b4 [2] 85 a9 [2] 87 a8 [2] 9c ae [2] 80 a9 [2] 9c 86 }

  condition:
    any of them
}