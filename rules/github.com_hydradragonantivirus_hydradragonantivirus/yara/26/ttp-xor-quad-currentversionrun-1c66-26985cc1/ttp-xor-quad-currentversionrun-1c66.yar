rule TTP_XOR_QUAD_CurrentVersionRun_1c66 {
  strings:
    $key_1c66 = { 4f 09 [2] 6b 07 [2] 40 2b [2] 6e 09 [2] 7a 12 [2] 75 08 [2] 6b 15 [2] 69 14 [2] 72 12 [2] 6e 15 [2] 72 3a }

  condition:
    any of them
}