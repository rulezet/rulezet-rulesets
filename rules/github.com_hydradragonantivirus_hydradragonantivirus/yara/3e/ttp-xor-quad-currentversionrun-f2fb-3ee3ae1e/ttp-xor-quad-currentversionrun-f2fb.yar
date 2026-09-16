rule TTP_XOR_QUAD_CurrentVersionRun_f2fb {
  strings:
    $key_f2fb = { a1 94 [2] 85 9a [2] ae b6 [2] 80 94 [2] 94 8f [2] 9b 95 [2] 85 88 [2] 87 89 [2] 9c 8f [2] 80 88 [2] 9c a7 }

  condition:
    any of them
}