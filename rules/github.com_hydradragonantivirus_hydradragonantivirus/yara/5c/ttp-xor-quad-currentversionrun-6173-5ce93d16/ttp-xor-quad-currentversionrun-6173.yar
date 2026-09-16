rule TTP_XOR_QUAD_CurrentVersionRun_6173 {
  strings:
    $key_6173 = { 32 1c [2] 16 12 [2] 3d 3e [2] 13 1c [2] 07 07 [2] 08 1d [2] 16 00 [2] 14 01 [2] 0f 07 [2] 13 00 [2] 0f 2f }

  condition:
    any of them
}