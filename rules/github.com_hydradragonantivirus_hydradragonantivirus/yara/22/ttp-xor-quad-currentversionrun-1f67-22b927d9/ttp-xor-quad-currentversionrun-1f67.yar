rule TTP_XOR_QUAD_CurrentVersionRun_1f67 {
  strings:
    $key_1f67 = { 4c 08 [2] 68 06 [2] 43 2a [2] 6d 08 [2] 79 13 [2] 76 09 [2] 68 14 [2] 6a 15 [2] 71 13 [2] 6d 14 [2] 71 3b }

  condition:
    any of them
}