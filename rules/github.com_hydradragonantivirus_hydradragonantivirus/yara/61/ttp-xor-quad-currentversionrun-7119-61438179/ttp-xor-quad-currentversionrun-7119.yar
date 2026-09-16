rule TTP_XOR_QUAD_CurrentVersionRun_7119 {
  strings:
    $key_7119 = { 22 76 [2] 06 78 [2] 2d 54 [2] 03 76 [2] 17 6d [2] 18 77 [2] 06 6a [2] 04 6b [2] 1f 6d [2] 03 6a [2] 1f 45 }

  condition:
    any of them
}