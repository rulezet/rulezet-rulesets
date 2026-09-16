rule TTP_XOR_QUAD_CurrentVersionRun_2567 {
  strings:
    $key_2567 = { 76 08 [2] 52 06 [2] 79 2a [2] 57 08 [2] 43 13 [2] 4c 09 [2] 52 14 [2] 50 15 [2] 4b 13 [2] 57 14 [2] 4b 3b }

  condition:
    any of them
}