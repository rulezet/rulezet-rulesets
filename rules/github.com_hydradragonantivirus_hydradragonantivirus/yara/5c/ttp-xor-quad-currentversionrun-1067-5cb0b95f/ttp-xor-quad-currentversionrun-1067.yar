rule TTP_XOR_QUAD_CurrentVersionRun_1067 {
  strings:
    $key_1067 = { 43 08 [2] 67 06 [2] 4c 2a [2] 62 08 [2] 76 13 [2] 79 09 [2] 67 14 [2] 65 15 [2] 7e 13 [2] 62 14 [2] 7e 3b }

  condition:
    any of them
}