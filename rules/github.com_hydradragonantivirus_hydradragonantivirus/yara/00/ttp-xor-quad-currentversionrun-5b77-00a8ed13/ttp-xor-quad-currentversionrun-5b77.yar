rule TTP_XOR_QUAD_CurrentVersionRun_5b77 {
  strings:
    $key_5b77 = { 08 18 [2] 2c 16 [2] 07 3a [2] 29 18 [2] 3d 03 [2] 32 19 [2] 2c 04 [2] 2e 05 [2] 35 03 [2] 29 04 [2] 35 2b }

  condition:
    any of them
}