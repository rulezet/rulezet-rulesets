rule TTP_XOR_QUAD_CurrentVersionRun_5e76 {
  strings:
    $key_5e76 = { 0d 19 [2] 29 17 [2] 02 3b [2] 2c 19 [2] 38 02 [2] 37 18 [2] 29 05 [2] 2b 04 [2] 30 02 [2] 2c 05 [2] 30 2a }

  condition:
    any of them
}