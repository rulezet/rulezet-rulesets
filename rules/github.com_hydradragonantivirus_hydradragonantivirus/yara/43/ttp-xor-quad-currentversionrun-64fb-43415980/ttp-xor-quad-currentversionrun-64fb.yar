rule TTP_XOR_QUAD_CurrentVersionRun_64fb {
  strings:
    $key_64fb = { 37 94 [2] 13 9a [2] 38 b6 [2] 16 94 [2] 02 8f [2] 0d 95 [2] 13 88 [2] 11 89 [2] 0a 8f [2] 16 88 [2] 0a a7 }

  condition:
    any of them
}