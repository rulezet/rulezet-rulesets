rule TTP_XOR_QUAD_CurrentVersionRun_f0fb {
  strings:
    $key_f0fb = { a3 94 [2] 87 9a [2] ac b6 [2] 82 94 [2] 96 8f [2] 99 95 [2] 87 88 [2] 85 89 [2] 9e 8f [2] 82 88 [2] 9e a7 }

  condition:
    any of them
}