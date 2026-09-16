rule TTP_XOR_QUAD_CurrentVersionRun_fada {
  strings:
    $key_fada = { a9 b5 [2] 8d bb [2] a6 97 [2] 88 b5 [2] 9c ae [2] 93 b4 [2] 8d a9 [2] 8f a8 [2] 94 ae [2] 88 a9 [2] 94 86 }

  condition:
    any of them
}