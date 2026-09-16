rule TTP_XOR_QUAD_CurrentVersionRun_5a74 {
  strings:
    $key_5a74 = { 09 1b [2] 2d 15 [2] 06 39 [2] 28 1b [2] 3c 00 [2] 33 1a [2] 2d 07 [2] 2f 06 [2] 34 00 [2] 28 07 [2] 34 28 }

  condition:
    any of them
}