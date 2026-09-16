rule TTP_XOR_QUAD_CurrentVersionRun_5469 {
  strings:
    $key_5469 = { 07 06 [2] 23 08 [2] 08 24 [2] 26 06 [2] 32 1d [2] 3d 07 [2] 23 1a [2] 21 1b [2] 3a 1d [2] 26 1a [2] 3a 35 }

  condition:
    any of them
}