rule TTP_XOR_QUAD_CurrentVersionRun_f0da {
  strings:
    $key_f0da = { a3 b5 [2] 87 bb [2] ac 97 [2] 82 b5 [2] 96 ae [2] 99 b4 [2] 87 a9 [2] 85 a8 [2] 9e ae [2] 82 a9 [2] 9e 86 }

  condition:
    any of them
}