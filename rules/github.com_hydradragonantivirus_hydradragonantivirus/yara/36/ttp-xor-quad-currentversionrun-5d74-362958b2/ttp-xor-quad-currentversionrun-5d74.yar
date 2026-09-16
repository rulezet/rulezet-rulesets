rule TTP_XOR_QUAD_CurrentVersionRun_5d74 {
  strings:
    $key_5d74 = { 0e 1b [2] 2a 15 [2] 01 39 [2] 2f 1b [2] 3b 00 [2] 34 1a [2] 2a 07 [2] 28 06 [2] 33 00 [2] 2f 07 [2] 33 28 }

  condition:
    any of them
}