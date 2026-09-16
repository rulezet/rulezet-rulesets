rule TTP_XOR_QUAD_CurrentVersionRun_6549 {
  strings:
    $key_6549 = { 36 26 [2] 12 28 [2] 39 04 [2] 17 26 [2] 03 3d [2] 0c 27 [2] 12 3a [2] 10 3b [2] 0b 3d [2] 17 3a [2] 0b 15 }

  condition:
    any of them
}