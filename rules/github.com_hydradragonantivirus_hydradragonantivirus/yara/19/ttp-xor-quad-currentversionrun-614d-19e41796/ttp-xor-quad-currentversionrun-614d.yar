rule TTP_XOR_QUAD_CurrentVersionRun_614d {
  strings:
    $key_614d = { 32 22 [2] 16 2c [2] 3d 00 [2] 13 22 [2] 07 39 [2] 08 23 [2] 16 3e [2] 14 3f [2] 0f 39 [2] 13 3e [2] 0f 11 }

  condition:
    any of them
}