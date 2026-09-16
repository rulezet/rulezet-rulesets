rule TTP_XOR_QUAD_CurrentVersionRun_7565 {
  strings:
    $key_7565 = { 26 0a [2] 02 04 [2] 29 28 [2] 07 0a [2] 13 11 [2] 1c 0b [2] 02 16 [2] 00 17 [2] 1b 11 [2] 07 16 [2] 1b 39 }

  condition:
    any of them
}