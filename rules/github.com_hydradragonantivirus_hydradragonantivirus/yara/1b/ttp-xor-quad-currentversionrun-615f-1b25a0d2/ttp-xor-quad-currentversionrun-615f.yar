rule TTP_XOR_QUAD_CurrentVersionRun_615f {
  strings:
    $key_615f = { 32 30 [2] 16 3e [2] 3d 12 [2] 13 30 [2] 07 2b [2] 08 31 [2] 16 2c [2] 14 2d [2] 0f 2b [2] 13 2c [2] 0f 03 }

  condition:
    any of them
}