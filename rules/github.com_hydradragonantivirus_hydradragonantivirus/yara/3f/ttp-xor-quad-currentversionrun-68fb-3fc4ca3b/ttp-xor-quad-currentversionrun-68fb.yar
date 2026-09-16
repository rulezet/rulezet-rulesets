rule TTP_XOR_QUAD_CurrentVersionRun_68fb {
  strings:
    $key_68fb = { 3b 94 [2] 1f 9a [2] 34 b6 [2] 1a 94 [2] 0e 8f [2] 01 95 [2] 1f 88 [2] 1d 89 [2] 06 8f [2] 1a 88 [2] 06 a7 }

  condition:
    any of them
}