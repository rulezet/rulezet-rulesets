rule TTP_XOR_QUAD_CurrentVersionRun_c80d {
  strings:
    $key_c80d = { 9b 62 [2] bf 6c [2] 94 40 [2] ba 62 [2] ae 79 [2] a1 63 [2] bf 7e [2] bd 7f [2] a6 79 [2] ba 7e [2] a6 51 }

  condition:
    any of them
}