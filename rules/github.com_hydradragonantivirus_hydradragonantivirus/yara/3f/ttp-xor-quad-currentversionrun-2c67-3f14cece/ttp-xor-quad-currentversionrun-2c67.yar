rule TTP_XOR_QUAD_CurrentVersionRun_2c67 {
  strings:
    $key_2c67 = { 7f 08 [2] 5b 06 [2] 70 2a [2] 5e 08 [2] 4a 13 [2] 45 09 [2] 5b 14 [2] 59 15 [2] 42 13 [2] 5e 14 [2] 42 3b }

  condition:
    any of them
}