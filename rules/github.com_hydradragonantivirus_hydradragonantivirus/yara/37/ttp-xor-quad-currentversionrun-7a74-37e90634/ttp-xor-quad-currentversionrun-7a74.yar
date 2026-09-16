rule TTP_XOR_QUAD_CurrentVersionRun_7a74 {
  strings:
    $key_7a74 = { 29 1b [2] 0d 15 [2] 26 39 [2] 08 1b [2] 1c 00 [2] 13 1a [2] 0d 07 [2] 0f 06 [2] 14 00 [2] 08 07 [2] 14 28 }

  condition:
    any of them
}