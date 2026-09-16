rule TTP_XOR_QUAD_CurrentVersionRun_f1fb {
  strings:
    $key_f1fb = { a2 94 [2] 86 9a [2] ad b6 [2] 83 94 [2] 97 8f [2] 98 95 [2] 86 88 [2] 84 89 [2] 9f 8f [2] 83 88 [2] 9f a7 }

  condition:
    any of them
}