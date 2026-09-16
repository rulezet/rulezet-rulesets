rule TTP_XOR_QUAD_CurrentVersionRun_0b67 {
  strings:
    $key_0b67 = { 58 08 [2] 7c 06 [2] 57 2a [2] 79 08 [2] 6d 13 [2] 62 09 [2] 7c 14 [2] 7e 15 [2] 65 13 [2] 79 14 [2] 65 3b }

  condition:
    any of them
}