rule TTP_XOR_QUAD_CurrentVersionRun_5b27 {
  strings:
    $key_5b27 = { 08 48 [2] 2c 46 [2] 07 6a [2] 29 48 [2] 3d 53 [2] 32 49 [2] 2c 54 [2] 2e 55 [2] 35 53 [2] 29 54 [2] 35 7b }

  condition:
    any of them
}