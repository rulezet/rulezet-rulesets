rule TTP_XOR_QUAD_CurrentVersionRun_5e77 {
  strings:
    $key_5e77 = { 0d 18 [2] 29 16 [2] 02 3a [2] 2c 18 [2] 38 03 [2] 37 19 [2] 29 04 [2] 2b 05 [2] 30 03 [2] 2c 04 [2] 30 2b }

  condition:
    any of them
}