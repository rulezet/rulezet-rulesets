rule TTP_XOR_QUAD_CurrentVersionRun_7967 {
  strings:
    $key_7967 = { 2a 08 [2] 0e 06 [2] 25 2a [2] 0b 08 [2] 1f 13 [2] 10 09 [2] 0e 14 [2] 0c 15 [2] 17 13 [2] 0b 14 [2] 17 3b }

  condition:
    any of them
}