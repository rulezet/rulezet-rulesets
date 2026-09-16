rule TTP_XOR_QUAD_CurrentVersionRun_5b39 {
  strings:
    $key_5b39 = { 08 56 [2] 2c 58 [2] 07 74 [2] 29 56 [2] 3d 4d [2] 32 57 [2] 2c 4a [2] 2e 4b [2] 35 4d [2] 29 4a [2] 35 65 }

  condition:
    any of them
}