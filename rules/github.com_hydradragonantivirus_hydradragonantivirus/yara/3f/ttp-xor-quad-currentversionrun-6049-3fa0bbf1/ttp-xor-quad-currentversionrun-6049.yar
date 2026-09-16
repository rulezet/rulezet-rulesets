rule TTP_XOR_QUAD_CurrentVersionRun_6049 {
  strings:
    $key_6049 = { 33 26 [2] 17 28 [2] 3c 04 [2] 12 26 [2] 06 3d [2] 09 27 [2] 17 3a [2] 15 3b [2] 0e 3d [2] 12 3a [2] 0e 15 }

  condition:
    any of them
}