rule TTP_XOR_QUAD_CurrentVersionRun_c8ef {
  strings:
    $key_c8ef = { 9b 80 [2] bf 8e [2] 94 a2 [2] ba 80 [2] ae 9b [2] a1 81 [2] bf 9c [2] bd 9d [2] a6 9b [2] ba 9c [2] a6 b3 }

  condition:
    any of them
}