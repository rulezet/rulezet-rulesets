rule TTP_XOR_QUAD_CurrentVersionRun_5966 {
  strings:
    $key_5966 = { 0a 09 [2] 2e 07 [2] 05 2b [2] 2b 09 [2] 3f 12 [2] 30 08 [2] 2e 15 [2] 2c 14 [2] 37 12 [2] 2b 15 [2] 37 3a }

  condition:
    any of them
}