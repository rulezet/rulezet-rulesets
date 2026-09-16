rule TTP_XOR_QUAD_CurrentVersionRun_f5fb {
  strings:
    $key_f5fb = { a6 94 [2] 82 9a [2] a9 b6 [2] 87 94 [2] 93 8f [2] 9c 95 [2] 82 88 [2] 80 89 [2] 9b 8f [2] 87 88 [2] 9b a7 }

  condition:
    any of them
}