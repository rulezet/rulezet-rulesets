rule TTP_XOR_QUAD_CurrentVersionRun_c87d {
  strings:
    $key_c87d = { 9b 12 [2] bf 1c [2] 94 30 [2] ba 12 [2] ae 09 [2] a1 13 [2] bf 0e [2] bd 0f [2] a6 09 [2] ba 0e [2] a6 21 }

  condition:
    any of them
}