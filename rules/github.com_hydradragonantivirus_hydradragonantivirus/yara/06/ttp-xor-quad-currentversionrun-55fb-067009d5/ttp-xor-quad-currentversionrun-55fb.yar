rule TTP_XOR_QUAD_CurrentVersionRun_55fb {
  strings:
    $key_55fb = { 06 94 [2] 22 9a [2] 09 b6 [2] 27 94 [2] 33 8f [2] 3c 95 [2] 22 88 [2] 20 89 [2] 3b 8f [2] 27 88 [2] 3b a7 }

  condition:
    any of them
}