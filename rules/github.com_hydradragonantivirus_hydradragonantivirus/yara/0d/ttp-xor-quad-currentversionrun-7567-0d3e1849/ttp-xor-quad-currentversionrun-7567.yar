rule TTP_XOR_QUAD_CurrentVersionRun_7567 {
  strings:
    $key_7567 = { 26 08 [2] 02 06 [2] 29 2a [2] 07 08 [2] 13 13 [2] 1c 09 [2] 02 14 [2] 00 15 [2] 1b 13 [2] 07 14 [2] 1b 3b }

  condition:
    any of them
}