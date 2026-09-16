rule TTP_XOR_QUAD_CurrentVersionRun_4374 {
  strings:
    $key_4374 = { 10 1b [2] 34 15 [2] 1f 39 [2] 31 1b [2] 25 00 [2] 2a 1a [2] 34 07 [2] 36 06 [2] 2d 00 [2] 31 07 [2] 2d 28 }

  condition:
    any of them
}