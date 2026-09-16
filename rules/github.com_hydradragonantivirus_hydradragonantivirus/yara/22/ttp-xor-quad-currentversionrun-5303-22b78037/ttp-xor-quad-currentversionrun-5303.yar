rule TTP_XOR_QUAD_CurrentVersionRun_5303 {
  strings:
    $key_5303 = { 00 6c [2] 24 62 [2] 0f 4e [2] 21 6c [2] 35 77 [2] 3a 6d [2] 24 70 [2] 26 71 [2] 3d 77 [2] 21 70 [2] 3d 5f }

  condition:
    any of them
}