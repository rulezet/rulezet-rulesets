rule TTP_XOR_QUAD_CurrentVersionRun_1567 {
  strings:
    $key_1567 = { 46 08 [2] 62 06 [2] 49 2a [2] 67 08 [2] 73 13 [2] 7c 09 [2] 62 14 [2] 60 15 [2] 7b 13 [2] 67 14 [2] 7b 3b }

  condition:
    any of them
}