rule TTP_XOR_QUAD_CurrentVersionRun_79fb {
  strings:
    $key_79fb = { 2a 94 [2] 0e 9a [2] 25 b6 [2] 0b 94 [2] 1f 8f [2] 10 95 [2] 0e 88 [2] 0c 89 [2] 17 8f [2] 0b 88 [2] 17 a7 }

  condition:
    any of them
}