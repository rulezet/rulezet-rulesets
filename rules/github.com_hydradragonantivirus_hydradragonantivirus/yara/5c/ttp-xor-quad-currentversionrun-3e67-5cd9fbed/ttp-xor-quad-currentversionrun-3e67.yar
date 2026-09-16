rule TTP_XOR_QUAD_CurrentVersionRun_3e67 {
  strings:
    $key_3e67 = { 6d 08 [2] 49 06 [2] 62 2a [2] 4c 08 [2] 58 13 [2] 57 09 [2] 49 14 [2] 4b 15 [2] 50 13 [2] 4c 14 [2] 50 3b }

  condition:
    any of them
}