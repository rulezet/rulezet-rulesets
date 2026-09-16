rule TTP_XOR_QUAD_CurrentVersionRun_c81c {
  strings:
    $key_c81c = { 9b 73 [2] bf 7d [2] 94 51 [2] ba 73 [2] ae 68 [2] a1 72 [2] bf 6f [2] bd 6e [2] a6 68 [2] ba 6f [2] a6 40 }

  condition:
    any of them
}