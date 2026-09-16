rule TTP_XOR_QUAD_CurrentVersionRun_2a67 {
  strings:
    $key_2a67 = { 79 08 [2] 5d 06 [2] 76 2a [2] 58 08 [2] 4c 13 [2] 43 09 [2] 5d 14 [2] 5f 15 [2] 44 13 [2] 58 14 [2] 44 3b }

  condition:
    any of them
}