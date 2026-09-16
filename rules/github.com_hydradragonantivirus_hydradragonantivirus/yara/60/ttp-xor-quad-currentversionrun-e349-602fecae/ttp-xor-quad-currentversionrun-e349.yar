rule TTP_XOR_QUAD_CurrentVersionRun_e349 {
  strings:
    $key_e349 = { b0 26 [2] 94 28 [2] bf 04 [2] 91 26 [2] 85 3d [2] 8a 27 [2] 94 3a [2] 96 3b [2] 8d 3d [2] 91 3a [2] 8d 15 }

  condition:
    any of them
}