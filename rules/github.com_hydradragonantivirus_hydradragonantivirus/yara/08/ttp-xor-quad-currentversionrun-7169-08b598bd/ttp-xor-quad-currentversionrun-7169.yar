rule TTP_XOR_QUAD_CurrentVersionRun_7169 {
  strings:
    $key_7169 = { 22 06 [2] 06 08 [2] 2d 24 [2] 03 06 [2] 17 1d [2] 18 07 [2] 06 1a [2] 04 1b [2] 1f 1d [2] 03 1a [2] 1f 35 }

  condition:
    any of them
}