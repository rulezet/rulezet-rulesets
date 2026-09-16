rule TTP_XOR_QUAD_CurrentVersionRun_7575 {
  strings:
    $key_7575 = { 26 1a [2] 02 14 [2] 29 38 [2] 07 1a [2] 13 01 [2] 1c 1b [2] 02 06 [2] 00 07 [2] 1b 01 [2] 07 06 [2] 1b 29 }

  condition:
    any of them
}