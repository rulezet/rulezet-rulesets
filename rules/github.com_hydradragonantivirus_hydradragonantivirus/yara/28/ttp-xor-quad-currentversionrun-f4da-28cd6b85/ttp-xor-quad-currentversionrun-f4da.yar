rule TTP_XOR_QUAD_CurrentVersionRun_f4da {
  strings:
    $key_f4da = { a7 b5 [2] 83 bb [2] a8 97 [2] 86 b5 [2] 92 ae [2] 9d b4 [2] 83 a9 [2] 81 a8 [2] 9a ae [2] 86 a9 [2] 9a 86 }

  condition:
    any of them
}