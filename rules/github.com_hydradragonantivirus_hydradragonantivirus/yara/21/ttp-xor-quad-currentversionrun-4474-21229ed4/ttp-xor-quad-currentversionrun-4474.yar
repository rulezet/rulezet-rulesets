rule TTP_XOR_QUAD_CurrentVersionRun_4474 {
  strings:
    $key_4474 = { 17 1b [2] 33 15 [2] 18 39 [2] 36 1b [2] 22 00 [2] 2d 1a [2] 33 07 [2] 31 06 [2] 2a 00 [2] 36 07 [2] 2a 28 }

  condition:
    any of them
}