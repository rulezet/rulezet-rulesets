rule TTP_XOR_QUAD_CurrentVersionRun_545f {
  strings:
    $key_545f = { 07 30 [2] 23 3e [2] 08 12 [2] 26 30 [2] 32 2b [2] 3d 31 [2] 23 2c [2] 21 2d [2] 3a 2b [2] 26 2c [2] 3a 03 }

  condition:
    any of them
}