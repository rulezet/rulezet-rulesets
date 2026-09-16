rule TTP_XOR_QUAD_CurrentVersionRun_66fb {
  strings:
    $key_66fb = { 35 94 [2] 11 9a [2] 3a b6 [2] 14 94 [2] 00 8f [2] 0f 95 [2] 11 88 [2] 13 89 [2] 08 8f [2] 14 88 [2] 08 a7 }

  condition:
    any of them
}