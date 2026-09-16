rule TTP_XOR_QUAD_CurrentVersionRun_4347 {
  strings:
    $key_4347 = { 10 28 [2] 34 26 [2] 1f 0a [2] 31 28 [2] 25 33 [2] 2a 29 [2] 34 34 [2] 36 35 [2] 2d 33 [2] 31 34 [2] 2d 1b }

  condition:
    any of them
}