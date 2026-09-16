rule TTP_XOR_QUAD_CurrentVersionRun_6a74 {
  strings:
    $key_6a74 = { 39 1b [2] 1d 15 [2] 36 39 [2] 18 1b [2] 0c 00 [2] 03 1a [2] 1d 07 [2] 1f 06 [2] 04 00 [2] 18 07 [2] 04 28 }

  condition:
    any of them
}