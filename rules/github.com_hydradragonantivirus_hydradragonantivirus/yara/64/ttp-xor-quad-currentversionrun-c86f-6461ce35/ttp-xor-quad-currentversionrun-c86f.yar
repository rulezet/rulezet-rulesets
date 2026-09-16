rule TTP_XOR_QUAD_CurrentVersionRun_c86f {
  strings:
    $key_c86f = { 9b 00 [2] bf 0e [2] 94 22 [2] ba 00 [2] ae 1b [2] a1 01 [2] bf 1c [2] bd 1d [2] a6 1b [2] ba 1c [2] a6 33 }

  condition:
    any of them
}