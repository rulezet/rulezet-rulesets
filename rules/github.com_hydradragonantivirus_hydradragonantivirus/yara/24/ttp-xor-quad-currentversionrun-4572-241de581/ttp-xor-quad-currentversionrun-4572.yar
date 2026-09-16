rule TTP_XOR_QUAD_CurrentVersionRun_4572 {
  strings:
    $key_4572 = { 16 1d [2] 32 13 [2] 19 3f [2] 37 1d [2] 23 06 [2] 2c 1c [2] 32 01 [2] 30 00 [2] 2b 06 [2] 37 01 [2] 2b 2e }

  condition:
    any of them
}