rule TTP_XOR_QUAD_CurrentVersionRun_4357 {
  strings:
    $key_4357 = { 10 38 [2] 34 36 [2] 1f 1a [2] 31 38 [2] 25 23 [2] 2a 39 [2] 34 24 [2] 36 25 [2] 2d 23 [2] 31 24 [2] 2d 0b }

  condition:
    any of them
}