rule TTP_XOR_QUAD_CurrentVersionRun_6567 {
  strings:
    $key_6567 = { 36 08 [2] 12 06 [2] 39 2a [2] 17 08 [2] 03 13 [2] 0c 09 [2] 12 14 [2] 10 15 [2] 0b 13 [2] 17 14 [2] 0b 3b }

  condition:
    any of them
}