rule TTP_XOR_QUAD_CurrentVersionRun_7173 {
  strings:
    $key_7173 = { 22 1c [2] 06 12 [2] 2d 3e [2] 03 1c [2] 17 07 [2] 18 1d [2] 06 00 [2] 04 01 [2] 1f 07 [2] 03 00 [2] 1f 2f }

  condition:
    any of them
}