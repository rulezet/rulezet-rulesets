rule TTP_XOR_QUAD_CurrentVersionRun_7f66 {
  strings:
    $key_7f66 = { 2c 09 [2] 08 07 [2] 23 2b [2] 0d 09 [2] 19 12 [2] 16 08 [2] 08 15 [2] 0a 14 [2] 11 12 [2] 0d 15 [2] 11 3a }

  condition:
    any of them
}