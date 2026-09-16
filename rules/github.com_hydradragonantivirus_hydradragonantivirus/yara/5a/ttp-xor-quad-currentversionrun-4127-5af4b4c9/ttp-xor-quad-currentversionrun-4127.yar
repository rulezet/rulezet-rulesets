rule TTP_XOR_QUAD_CurrentVersionRun_4127 {
  strings:
    $key_4127 = { 12 48 [2] 36 46 [2] 1d 6a [2] 33 48 [2] 27 53 [2] 28 49 [2] 36 54 [2] 34 55 [2] 2f 53 [2] 33 54 [2] 2f 7b }

  condition:
    any of them
}