rule TTP_XOR_QUAD_CurrentVersionRun_7974 {
  strings:
    $key_7974 = { 2a 1b [2] 0e 15 [2] 25 39 [2] 0b 1b [2] 1f 00 [2] 10 1a [2] 0e 07 [2] 0c 06 [2] 17 00 [2] 0b 07 [2] 17 28 }

  condition:
    any of them
}