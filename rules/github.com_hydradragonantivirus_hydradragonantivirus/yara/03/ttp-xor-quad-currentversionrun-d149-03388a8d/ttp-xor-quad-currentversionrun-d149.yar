rule TTP_XOR_QUAD_CurrentVersionRun_d149 {
  strings:
    $key_d149 = { 82 26 [2] a6 28 [2] 8d 04 [2] a3 26 [2] b7 3d [2] b8 27 [2] a6 3a [2] a4 3b [2] bf 3d [2] a3 3a [2] bf 15 }

  condition:
    any of them
}