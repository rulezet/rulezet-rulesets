rule TTP_XOR_QUAD_CurrentVersionRun_d649 {
  strings:
    $key_d649 = { 85 26 [2] a1 28 [2] 8a 04 [2] a4 26 [2] b0 3d [2] bf 27 [2] a1 3a [2] a3 3b [2] b8 3d [2] a4 3a [2] b8 15 }

  condition:
    any of them
}