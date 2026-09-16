rule TTP_XOR_QUAD_CurrentVersionRun_7c66 {
  strings:
    $key_7c66 = { 2f 09 [2] 0b 07 [2] 20 2b [2] 0e 09 [2] 1a 12 [2] 15 08 [2] 0b 15 [2] 09 14 [2] 12 12 [2] 0e 15 [2] 12 3a }

  condition:
    any of them
}