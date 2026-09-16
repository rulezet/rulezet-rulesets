rule TTP_XOR_QUAD_CurrentVersionRun_2a74 {
  strings:
    $key_2a74 = { 79 1b [2] 5d 15 [2] 76 39 [2] 58 1b [2] 4c 00 [2] 43 1a [2] 5d 07 [2] 5f 06 [2] 44 00 [2] 58 07 [2] 44 28 }

  condition:
    any of them
}