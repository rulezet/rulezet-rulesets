rule TTP_XOR_QUAD_CurrentVersionRun_5549 {
  strings:
    $key_5549 = { 06 26 [2] 22 28 [2] 09 04 [2] 27 26 [2] 33 3d [2] 3c 27 [2] 22 3a [2] 20 3b [2] 3b 3d [2] 27 3a [2] 3b 15 }

  condition:
    any of them
}