rule TTP_XOR_QUAD_CurrentVersionRun_4f69 {
  strings:
    $key_4f69 = { 1c 06 [2] 38 08 [2] 13 24 [2] 3d 06 [2] 29 1d [2] 26 07 [2] 38 1a [2] 3a 1b [2] 21 1d [2] 3d 1a [2] 21 35 }

  condition:
    any of them
}