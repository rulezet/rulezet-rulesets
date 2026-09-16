rule TTP_XOR_QUAD_CurrentVersionRun_5574 {
  strings:
    $key_5574 = { 06 1b [2] 22 15 [2] 09 39 [2] 27 1b [2] 33 00 [2] 3c 1a [2] 22 07 [2] 20 06 [2] 3b 00 [2] 27 07 [2] 3b 28 }

  condition:
    any of them
}