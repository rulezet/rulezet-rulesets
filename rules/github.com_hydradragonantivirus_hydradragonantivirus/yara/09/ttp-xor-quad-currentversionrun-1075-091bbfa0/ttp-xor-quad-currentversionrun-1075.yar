rule TTP_XOR_QUAD_CurrentVersionRun_1075 {
  strings:
    $key_1075 = { 43 1a [2] 67 14 [2] 4c 38 [2] 62 1a [2] 76 01 [2] 79 1b [2] 67 06 [2] 65 07 [2] 7e 01 [2] 62 06 [2] 7e 29 }

  condition:
    any of them
}