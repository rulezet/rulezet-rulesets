rule TTP_XOR_QUAD_CurrentVersionRun_7b67 {
  strings:
    $key_7b67 = { 28 08 [2] 0c 06 [2] 27 2a [2] 09 08 [2] 1d 13 [2] 12 09 [2] 0c 14 [2] 0e 15 [2] 15 13 [2] 09 14 [2] 15 3b }

  condition:
    any of them
}