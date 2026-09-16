rule TTP_XOR_QUAD_CurrentVersionRun_0b74 {
  strings:
    $key_0b74 = { 58 1b [2] 7c 15 [2] 57 39 [2] 79 1b [2] 6d 00 [2] 62 1a [2] 7c 07 [2] 7e 06 [2] 65 00 [2] 79 07 [2] 65 28 }

  condition:
    any of them
}