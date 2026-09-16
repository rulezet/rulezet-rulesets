rule TTP_XOR_QUAD_CurrentVersionRun_5473 {
  strings:
    $key_5473 = { 07 1c [2] 23 12 [2] 08 3e [2] 26 1c [2] 32 07 [2] 3d 1d [2] 23 00 [2] 21 01 [2] 3a 07 [2] 26 00 [2] 3a 2f }

  condition:
    any of them
}