rule TTP_XOR_QUAD_CurrentVersionRun_c82d {
  strings:
    $key_c82d = { 9b 42 [2] bf 4c [2] 94 60 [2] ba 42 [2] ae 59 [2] a1 43 [2] bf 5e [2] bd 5f [2] a6 59 [2] ba 5e [2] a6 71 }

  condition:
    any of them
}