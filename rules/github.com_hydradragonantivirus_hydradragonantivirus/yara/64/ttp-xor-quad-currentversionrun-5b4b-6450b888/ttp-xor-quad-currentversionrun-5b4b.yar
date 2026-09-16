rule TTP_XOR_QUAD_CurrentVersionRun_5b4b {
  strings:
    $key_5b4b = { 08 24 [2] 2c 2a [2] 07 06 [2] 29 24 [2] 3d 3f [2] 32 25 [2] 2c 38 [2] 2e 39 [2] 35 3f [2] 29 38 [2] 35 17 }

  condition:
    any of them
}