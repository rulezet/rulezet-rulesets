rule TTP_XOR_QUAD_CurrentVersionRun_c149 {
  strings:
    $key_c149 = { 92 26 [2] b6 28 [2] 9d 04 [2] b3 26 [2] a7 3d [2] a8 27 [2] b6 3a [2] b4 3b [2] af 3d [2] b3 3a [2] af 15 }

  condition:
    any of them
}