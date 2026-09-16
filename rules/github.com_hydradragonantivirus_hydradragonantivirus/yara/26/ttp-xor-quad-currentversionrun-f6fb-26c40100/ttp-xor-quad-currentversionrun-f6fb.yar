rule TTP_XOR_QUAD_CurrentVersionRun_f6fb {
  strings:
    $key_f6fb = { a5 94 [2] 81 9a [2] aa b6 [2] 84 94 [2] 90 8f [2] 9f 95 [2] 81 88 [2] 83 89 [2] 98 8f [2] 84 88 [2] 98 a7 }

  condition:
    any of them
}