rule TTP_XOR_QUAD_CurrentVersionRun_5149 {
  strings:
    $key_5149 = { 02 26 [2] 26 28 [2] 0d 04 [2] 23 26 [2] 37 3d [2] 38 27 [2] 26 3a [2] 24 3b [2] 3f 3d [2] 23 3a [2] 3f 15 }

  condition:
    any of them
}