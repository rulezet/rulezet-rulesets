rule TTP_XOR_QUAD_CurrentVersionRun_7118 {
  strings:
    $key_7118 = { 22 77 [2] 06 79 [2] 2d 55 [2] 03 77 [2] 17 6c [2] 18 76 [2] 06 6b [2] 04 6a [2] 1f 6c [2] 03 6b [2] 1f 44 }

  condition:
    any of them
}