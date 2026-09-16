rule TTP_XOR_QUAD_CurrentVersionRun_1549 {
  strings:
    $key_1549 = { 46 26 [2] 62 28 [2] 49 04 [2] 67 26 [2] 73 3d [2] 7c 27 [2] 62 3a [2] 60 3b [2] 7b 3d [2] 67 3a [2] 7b 15 }

  condition:
    any of them
}