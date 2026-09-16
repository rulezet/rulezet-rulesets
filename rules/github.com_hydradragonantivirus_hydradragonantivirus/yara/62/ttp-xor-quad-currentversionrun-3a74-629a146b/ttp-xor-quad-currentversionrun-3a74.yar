rule TTP_XOR_QUAD_CurrentVersionRun_3a74 {
  strings:
    $key_3a74 = { 69 1b [2] 4d 15 [2] 66 39 [2] 48 1b [2] 5c 00 [2] 53 1a [2] 4d 07 [2] 4f 06 [2] 54 00 [2] 48 07 [2] 54 28 }

  condition:
    any of them
}