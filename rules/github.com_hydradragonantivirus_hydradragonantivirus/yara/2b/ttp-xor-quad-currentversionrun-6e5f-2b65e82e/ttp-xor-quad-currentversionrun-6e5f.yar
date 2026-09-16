rule TTP_XOR_QUAD_CurrentVersionRun_6e5f {
  strings:
    $key_6e5f = { 3d 30 [2] 19 3e [2] 32 12 [2] 1c 30 [2] 08 2b [2] 07 31 [2] 19 2c [2] 1b 2d [2] 00 2b [2] 1c 2c [2] 00 03 }

  condition:
    any of them
}