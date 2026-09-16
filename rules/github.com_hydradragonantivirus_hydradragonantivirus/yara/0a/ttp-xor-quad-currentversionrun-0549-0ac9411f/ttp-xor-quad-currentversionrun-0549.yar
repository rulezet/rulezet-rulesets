rule TTP_XOR_QUAD_CurrentVersionRun_0549 {
  strings:
    $key_0549 = { 56 26 [2] 72 28 [2] 59 04 [2] 77 26 [2] 63 3d [2] 6c 27 [2] 72 3a [2] 70 3b [2] 6b 3d [2] 77 3a [2] 6b 15 }

  condition:
    any of them
}