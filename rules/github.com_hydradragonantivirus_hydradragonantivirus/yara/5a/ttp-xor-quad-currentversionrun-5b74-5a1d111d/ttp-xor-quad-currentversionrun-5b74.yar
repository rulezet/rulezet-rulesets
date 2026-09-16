rule TTP_XOR_QUAD_CurrentVersionRun_5b74 {
  strings:
    $key_5b74 = { 08 1b [2] 2c 15 [2] 07 39 [2] 29 1b [2] 3d 00 [2] 32 1a [2] 2c 07 [2] 2e 06 [2] 35 00 [2] 29 07 [2] 35 28 }

  condition:
    any of them
}