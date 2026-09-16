rule TTP_XOR_QUAD_CurrentVersionRun_5b6e {
  strings:
    $key_5b6e = { 08 01 [2] 2c 0f [2] 07 23 [2] 29 01 [2] 3d 1a [2] 32 00 [2] 2c 1d [2] 2e 1c [2] 35 1a [2] 29 1d [2] 35 32 }

  condition:
    any of them
}