rule TTP_XOR_QUAD_CurrentVersionRun_5b6f {
  strings:
    $key_5b6f = { 08 00 [2] 2c 0e [2] 07 22 [2] 29 00 [2] 3d 1b [2] 32 01 [2] 2c 1c [2] 2e 1d [2] 35 1b [2] 29 1c [2] 35 33 }

  condition:
    any of them
}