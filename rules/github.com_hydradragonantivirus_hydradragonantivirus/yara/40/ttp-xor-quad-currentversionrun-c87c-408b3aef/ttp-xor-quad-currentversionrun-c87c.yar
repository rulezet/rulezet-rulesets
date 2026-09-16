rule TTP_XOR_QUAD_CurrentVersionRun_c87c {
  strings:
    $key_c87c = { 9b 13 [2] bf 1d [2] 94 31 [2] ba 13 [2] ae 08 [2] a1 12 [2] bf 0f [2] bd 0e [2] a6 08 [2] ba 0f [2] a6 20 }

  condition:
    any of them
}