rule TTP_XOR_QUAD_CurrentVersionRun_c853 {
  strings:
    $key_c853 = { 9b 3c [2] bf 32 [2] 94 1e [2] ba 3c [2] ae 27 [2] a1 3d [2] bf 20 [2] bd 21 [2] a6 27 [2] ba 20 [2] a6 0f }

  condition:
    any of them
}