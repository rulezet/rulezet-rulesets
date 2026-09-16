rule TTP_XOR_QUAD_CurrentVersionRun_3b67 {
  strings:
    $key_3b67 = { 68 08 [2] 4c 06 [2] 67 2a [2] 49 08 [2] 5d 13 [2] 52 09 [2] 4c 14 [2] 4e 15 [2] 55 13 [2] 49 14 [2] 55 3b }

  condition:
    any of them
}