rule TTP_XOR_QUAD_CurrentVersionRun_5267 {
  strings:
    $key_5267 = { 01 08 [2] 25 06 [2] 0e 2a [2] 20 08 [2] 34 13 [2] 3b 09 [2] 25 14 [2] 27 15 [2] 3c 13 [2] 20 14 [2] 3c 3b }

  condition:
    any of them
}