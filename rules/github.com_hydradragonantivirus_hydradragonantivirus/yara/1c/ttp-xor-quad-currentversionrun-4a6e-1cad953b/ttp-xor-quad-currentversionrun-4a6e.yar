rule TTP_XOR_QUAD_CurrentVersionRun_4a6e {
  strings:
    $key_4a6e = { 19 01 [2] 3d 0f [2] 16 23 [2] 38 01 [2] 2c 1a [2] 23 00 [2] 3d 1d [2] 3f 1c [2] 24 1a [2] 38 1d [2] 24 32 }

  condition:
    any of them
}