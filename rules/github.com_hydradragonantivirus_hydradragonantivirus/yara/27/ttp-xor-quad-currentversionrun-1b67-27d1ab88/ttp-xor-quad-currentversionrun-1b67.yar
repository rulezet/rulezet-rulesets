rule TTP_XOR_QUAD_CurrentVersionRun_1b67 {
  strings:
    $key_1b67 = { 48 08 [2] 6c 06 [2] 47 2a [2] 69 08 [2] 7d 13 [2] 72 09 [2] 6c 14 [2] 6e 15 [2] 75 13 [2] 69 14 [2] 75 3b }

  condition:
    any of them
}