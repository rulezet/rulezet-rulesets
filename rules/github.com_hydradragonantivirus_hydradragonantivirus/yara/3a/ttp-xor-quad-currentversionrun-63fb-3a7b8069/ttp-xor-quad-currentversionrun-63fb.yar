rule TTP_XOR_QUAD_CurrentVersionRun_63fb {
  strings:
    $key_63fb = { 30 94 [2] 14 9a [2] 3f b6 [2] 11 94 [2] 05 8f [2] 0a 95 [2] 14 88 [2] 16 89 [2] 0d 8f [2] 11 88 [2] 0d a7 }

  condition:
    any of them
}