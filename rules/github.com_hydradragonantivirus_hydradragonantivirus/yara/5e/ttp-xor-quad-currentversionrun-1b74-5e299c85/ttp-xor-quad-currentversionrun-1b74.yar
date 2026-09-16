rule TTP_XOR_QUAD_CurrentVersionRun_1b74 {
  strings:
    $key_1b74 = { 48 1b [2] 6c 15 [2] 47 39 [2] 69 1b [2] 7d 00 [2] 72 1a [2] 6c 07 [2] 6e 06 [2] 75 00 [2] 69 07 [2] 75 28 }

  condition:
    any of them
}