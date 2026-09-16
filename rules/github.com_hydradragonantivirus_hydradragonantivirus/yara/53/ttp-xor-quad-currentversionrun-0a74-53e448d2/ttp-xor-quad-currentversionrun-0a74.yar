rule TTP_XOR_QUAD_CurrentVersionRun_0a74 {
  strings:
    $key_0a74 = { 59 1b [2] 7d 15 [2] 56 39 [2] 78 1b [2] 6c 00 [2] 63 1a [2] 7d 07 [2] 7f 06 [2] 64 00 [2] 78 07 [2] 64 28 }

  condition:
    any of them
}