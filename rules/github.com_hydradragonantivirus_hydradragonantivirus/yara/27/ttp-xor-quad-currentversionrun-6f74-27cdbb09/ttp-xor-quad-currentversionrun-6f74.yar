rule TTP_XOR_QUAD_CurrentVersionRun_6f74 {
  strings:
    $key_6f74 = { 3c 1b [2] 18 15 [2] 33 39 [2] 1d 1b [2] 09 00 [2] 06 1a [2] 18 07 [2] 1a 06 [2] 01 00 [2] 1d 07 [2] 01 28 }

  condition:
    any of them
}