rule TTP_XOR_QUAD_CurrentVersionRun_6067 {
  strings:
    $key_6067 = { 33 08 [2] 17 06 [2] 3c 2a [2] 12 08 [2] 06 13 [2] 09 09 [2] 17 14 [2] 15 15 [2] 0e 13 [2] 12 14 [2] 0e 3b }

  condition:
    any of them
}