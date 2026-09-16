rule TTP_XOR_QUAD_CurrentVersionRun_0c67 {
  strings:
    $key_0c67 = { 5f 08 [2] 7b 06 [2] 50 2a [2] 7e 08 [2] 6a 13 [2] 65 09 [2] 7b 14 [2] 79 15 [2] 62 13 [2] 7e 14 [2] 62 3b }

  condition:
    any of them
}