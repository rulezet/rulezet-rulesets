rule TTP_XOR_QUAD_CurrentVersionRun_75fb {
  strings:
    $key_75fb = { 26 94 [2] 02 9a [2] 29 b6 [2] 07 94 [2] 13 8f [2] 1c 95 [2] 02 88 [2] 00 89 [2] 1b 8f [2] 07 88 [2] 1b a7 }

  condition:
    any of them
}