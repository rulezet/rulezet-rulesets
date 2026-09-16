rule TTP_XOR_QUAD_CurrentVersionRun_6e5e {
  strings:
    $key_6e5e = { 3d 31 [2] 19 3f [2] 32 13 [2] 1c 31 [2] 08 2a [2] 07 30 [2] 19 2d [2] 1b 2c [2] 00 2a [2] 1c 2d [2] 00 02 }

  condition:
    any of them
}