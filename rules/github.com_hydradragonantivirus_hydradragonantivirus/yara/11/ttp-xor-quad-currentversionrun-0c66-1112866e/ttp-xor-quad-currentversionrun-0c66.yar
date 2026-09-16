rule TTP_XOR_QUAD_CurrentVersionRun_0c66 {
  strings:
    $key_0c66 = { 5f 09 [2] 7b 07 [2] 50 2b [2] 7e 09 [2] 6a 12 [2] 65 08 [2] 7b 15 [2] 79 14 [2] 62 12 [2] 7e 15 [2] 62 3a }

  condition:
    any of them
}