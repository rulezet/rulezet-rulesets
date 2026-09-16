rule TTP_XOR_QUAD_CurrentVersionRun_65fb {
  strings:
    $key_65fb = { 36 94 [2] 12 9a [2] 39 b6 [2] 17 94 [2] 03 8f [2] 0c 95 [2] 12 88 [2] 10 89 [2] 0b 8f [2] 17 88 [2] 0b a7 }

  condition:
    any of them
}