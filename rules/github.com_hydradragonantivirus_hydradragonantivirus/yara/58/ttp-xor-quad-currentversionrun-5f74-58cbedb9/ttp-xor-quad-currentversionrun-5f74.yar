rule TTP_XOR_QUAD_CurrentVersionRun_5f74 {
  strings:
    $key_5f74 = { 0c 1b [2] 28 15 [2] 03 39 [2] 2d 1b [2] 39 00 [2] 36 1a [2] 28 07 [2] 2a 06 [2] 31 00 [2] 2d 07 [2] 31 28 }

  condition:
    any of them
}