rule TTP_XOR_QUAD_CurrentVersionRun_7564 {
  strings:
    $key_7564 = { 26 0b [2] 02 05 [2] 29 29 [2] 07 0b [2] 13 10 [2] 1c 0a [2] 02 17 [2] 00 16 [2] 1b 10 [2] 07 17 [2] 1b 38 }

  condition:
    any of them
}