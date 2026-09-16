rule TTP_XOR_QUAD_CurrentVersionRun_4974 {
  strings:
    $key_4974 = { 1a 1b [2] 3e 15 [2] 15 39 [2] 3b 1b [2] 2f 00 [2] 20 1a [2] 3e 07 [2] 3c 06 [2] 27 00 [2] 3b 07 [2] 27 28 }

  condition:
    any of them
}