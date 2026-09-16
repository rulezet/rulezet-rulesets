rule TTP_XOR_QUAD_CurrentVersionRun_c8ed {
  strings:
    $key_c8ed = { 9b 82 [2] bf 8c [2] 94 a0 [2] ba 82 [2] ae 99 [2] a1 83 [2] bf 9e [2] bd 9f [2] a6 99 [2] ba 9e [2] a6 b1 }

  condition:
    any of them
}