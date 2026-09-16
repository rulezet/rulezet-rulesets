rule TTP_XOR_QUAD_CurrentVersionRun_c749 {
  strings:
    $key_c749 = { 94 26 [2] b0 28 [2] 9b 04 [2] b5 26 [2] a1 3d [2] ae 27 [2] b0 3a [2] b2 3b [2] a9 3d [2] b5 3a [2] a9 15 }

  condition:
    any of them
}