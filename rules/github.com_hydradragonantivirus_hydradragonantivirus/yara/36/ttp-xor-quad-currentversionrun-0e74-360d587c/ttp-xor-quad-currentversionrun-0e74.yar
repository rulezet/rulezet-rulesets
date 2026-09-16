rule TTP_XOR_QUAD_CurrentVersionRun_0e74 {
  strings:
    $key_0e74 = { 5d 1b [2] 79 15 [2] 52 39 [2] 7c 1b [2] 68 00 [2] 67 1a [2] 79 07 [2] 7b 06 [2] 60 00 [2] 7c 07 [2] 60 28 }

  condition:
    any of them
}