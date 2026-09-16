rule TTP_XOR_QUAD_CurrentVersionRun_c863 {
  strings:
    $key_c863 = { 9b 0c [2] bf 02 [2] 94 2e [2] ba 0c [2] ae 17 [2] a1 0d [2] bf 10 [2] bd 11 [2] a6 17 [2] ba 10 [2] a6 3f }

  condition:
    any of them
}