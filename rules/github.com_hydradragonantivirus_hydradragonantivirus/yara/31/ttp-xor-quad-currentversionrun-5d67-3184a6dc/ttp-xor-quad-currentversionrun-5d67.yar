rule TTP_XOR_QUAD_CurrentVersionRun_5d67 {
  strings:
    $key_5d67 = { 0e 08 [2] 2a 06 [2] 01 2a [2] 2f 08 [2] 3b 13 [2] 34 09 [2] 2a 14 [2] 28 15 [2] 33 13 [2] 2f 14 [2] 33 3b }

  condition:
    any of them
}