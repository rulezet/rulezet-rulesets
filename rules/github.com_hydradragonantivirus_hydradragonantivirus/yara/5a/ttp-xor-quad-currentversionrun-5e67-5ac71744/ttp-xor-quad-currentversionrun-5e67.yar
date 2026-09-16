rule TTP_XOR_QUAD_CurrentVersionRun_5e67 {
  strings:
    $key_5e67 = { 0d 08 [2] 29 06 [2] 02 2a [2] 2c 08 [2] 38 13 [2] 37 09 [2] 29 14 [2] 2b 15 [2] 30 13 [2] 2c 14 [2] 30 3b }

  condition:
    any of them
}