rule TTP_XOR_QUAD_CurrentVersionRun_f7da {
  strings:
    $key_f7da = { a4 b5 [2] 80 bb [2] ab 97 [2] 85 b5 [2] 91 ae [2] 9e b4 [2] 80 a9 [2] 82 a8 [2] 99 ae [2] 85 a9 [2] 99 86 }

  condition:
    any of them
}