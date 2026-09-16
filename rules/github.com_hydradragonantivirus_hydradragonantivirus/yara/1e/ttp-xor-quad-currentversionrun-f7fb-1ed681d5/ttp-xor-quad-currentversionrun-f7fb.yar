rule TTP_XOR_QUAD_CurrentVersionRun_f7fb {
  strings:
    $key_f7fb = { a4 94 [2] 80 9a [2] ab b6 [2] 85 94 [2] 91 8f [2] 9e 95 [2] 80 88 [2] 82 89 [2] 99 8f [2] 85 88 [2] 99 a7 }

  condition:
    any of them
}