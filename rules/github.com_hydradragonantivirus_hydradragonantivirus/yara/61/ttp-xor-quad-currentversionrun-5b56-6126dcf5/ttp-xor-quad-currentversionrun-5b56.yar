rule TTP_XOR_QUAD_CurrentVersionRun_5b56 {
  strings:
    $key_5b56 = { 08 39 [2] 2c 37 [2] 07 1b [2] 29 39 [2] 3d 22 [2] 32 38 [2] 2c 25 [2] 2e 24 [2] 35 22 [2] 29 25 [2] 35 0a }

  condition:
    any of them
}