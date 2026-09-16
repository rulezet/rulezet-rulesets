rule TTP_XOR_QUAD_CurrentVersionRun_5b5f {
  strings:
    $key_5b5f = { 08 30 [2] 2c 3e [2] 07 12 [2] 29 30 [2] 3d 2b [2] 32 31 [2] 2c 2c [2] 2e 2d [2] 35 2b [2] 29 2c [2] 35 03 }

  condition:
    any of them
}