rule TTP_XOR_QUAD_CurrentVersionRun_5849 {
  strings:
    $key_5849 = { 0b 26 [2] 2f 28 [2] 04 04 [2] 2a 26 [2] 3e 3d [2] 31 27 [2] 2f 3a [2] 2d 3b [2] 36 3d [2] 2a 3a [2] 36 15 }

  condition:
    any of them
}