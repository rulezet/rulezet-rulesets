rule TTP_XOR_QUAD_CurrentVersionRun_c81d {
  strings:
    $key_c81d = { 9b 72 [2] bf 7c [2] 94 50 [2] ba 72 [2] ae 69 [2] a1 73 [2] bf 6e [2] bd 6f [2] a6 69 [2] ba 6e [2] a6 41 }

  condition:
    any of them
}