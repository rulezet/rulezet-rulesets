rule TTP_XOR_QUAD_CurrentVersionRun_3149 {
  strings:
    $key_3149 = { 62 26 [2] 46 28 [2] 6d 04 [2] 43 26 [2] 57 3d [2] 58 27 [2] 46 3a [2] 44 3b [2] 5f 3d [2] 43 3a [2] 5f 15 }

  condition:
    any of them
}