rule TTP_XOR_QUAD_CurrentVersionRun_c86c {
  strings:
    $key_c86c = { 9b 03 [2] bf 0d [2] 94 21 [2] ba 03 [2] ae 18 [2] a1 02 [2] bf 1f [2] bd 1e [2] a6 18 [2] ba 1f [2] a6 30 }

  condition:
    any of them
}