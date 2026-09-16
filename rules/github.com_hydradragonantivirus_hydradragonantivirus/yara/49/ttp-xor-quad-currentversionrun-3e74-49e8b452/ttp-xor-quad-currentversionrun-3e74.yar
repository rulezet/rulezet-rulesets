rule TTP_XOR_QUAD_CurrentVersionRun_3e74 {
  strings:
    $key_3e74 = { 6d 1b [2] 49 15 [2] 62 39 [2] 4c 1b [2] 58 00 [2] 57 1a [2] 49 07 [2] 4b 06 [2] 50 00 [2] 4c 07 [2] 50 28 }

  condition:
    any of them
}