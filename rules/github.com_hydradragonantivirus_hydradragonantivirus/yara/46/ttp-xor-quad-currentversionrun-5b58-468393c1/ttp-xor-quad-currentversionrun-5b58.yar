rule TTP_XOR_QUAD_CurrentVersionRun_5b58 {
  strings:
    $key_5b58 = { 08 37 [2] 2c 39 [2] 07 15 [2] 29 37 [2] 3d 2c [2] 32 36 [2] 2c 2b [2] 2e 2a [2] 35 2c [2] 29 2b [2] 35 04 }

  condition:
    any of them
}