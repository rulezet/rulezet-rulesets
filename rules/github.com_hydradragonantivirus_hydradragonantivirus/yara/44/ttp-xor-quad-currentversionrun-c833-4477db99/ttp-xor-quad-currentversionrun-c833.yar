rule TTP_XOR_QUAD_CurrentVersionRun_c833 {
  strings:
    $key_c833 = { 9b 5c [2] bf 52 [2] 94 7e [2] ba 5c [2] ae 47 [2] a1 5d [2] bf 40 [2] bd 41 [2] a6 47 [2] ba 40 [2] a6 6f }

  condition:
    any of them
}