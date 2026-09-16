rule TTP_XOR_QUAD_CurrentVersionRun_7549 {
  strings:
    $key_7549 = { 26 26 [2] 02 28 [2] 29 04 [2] 07 26 [2] 13 3d [2] 1c 27 [2] 02 3a [2] 00 3b [2] 1b 3d [2] 07 3a [2] 1b 15 }

  condition:
    any of them
}