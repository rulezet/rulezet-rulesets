rule TTP_XOR_QUAD_CurrentVersionRun_4e67 {
  strings:
    $key_4e67 = { 1d 08 [2] 39 06 [2] 12 2a [2] 3c 08 [2] 28 13 [2] 27 09 [2] 39 14 [2] 3b 15 [2] 20 13 [2] 3c 14 [2] 20 3b }

  condition:
    any of them
}