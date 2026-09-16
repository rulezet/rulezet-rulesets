rule TTP_XOR_QUAD_CurrentVersionRun_5368 {
  strings:
    $key_5368 = { 00 07 [2] 24 09 [2] 0f 25 [2] 21 07 [2] 35 1c [2] 3a 06 [2] 24 1b [2] 26 1a [2] 3d 1c [2] 21 1b [2] 3d 34 }

  condition:
    any of them
}