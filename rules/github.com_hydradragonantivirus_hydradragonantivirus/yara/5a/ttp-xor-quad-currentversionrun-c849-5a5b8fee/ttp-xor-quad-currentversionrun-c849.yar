rule TTP_XOR_QUAD_CurrentVersionRun_c849 {
  strings:
    $key_c849 = { 9b 26 [2] bf 28 [2] 94 04 [2] ba 26 [2] ae 3d [2] a1 27 [2] bf 3a [2] bd 3b [2] a6 3d [2] ba 3a [2] a6 15 }

  condition:
    any of them
}