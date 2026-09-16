rule TTP_XOR_QUAD_CurrentVersionRun_7667 {
  strings:
    $key_7667 = { 25 08 [2] 01 06 [2] 2a 2a [2] 04 08 [2] 10 13 [2] 1f 09 [2] 01 14 [2] 03 15 [2] 18 13 [2] 04 14 [2] 18 3b }

  condition:
    any of them
}