rule TTP_XOR_QUAD_CurrentVersionRun_7f67 {
  strings:
    $key_7f67 = { 2c 08 [2] 08 06 [2] 23 2a [2] 0d 08 [2] 19 13 [2] 16 09 [2] 08 14 [2] 0a 15 [2] 11 13 [2] 0d 14 [2] 11 3b }

  condition:
    any of them
}