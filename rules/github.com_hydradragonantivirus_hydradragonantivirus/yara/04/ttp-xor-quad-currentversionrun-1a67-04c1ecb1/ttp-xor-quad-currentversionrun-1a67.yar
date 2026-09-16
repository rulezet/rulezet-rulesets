rule TTP_XOR_QUAD_CurrentVersionRun_1a67 {
  strings:
    $key_1a67 = { 49 08 [2] 6d 06 [2] 46 2a [2] 68 08 [2] 7c 13 [2] 73 09 [2] 6d 14 [2] 6f 15 [2] 74 13 [2] 68 14 [2] 74 3b }

  condition:
    any of them
}