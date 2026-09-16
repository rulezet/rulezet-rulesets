rule TTP_XOR_QUAD_CurrentVersionRun_c864 {
  strings:
    $key_c864 = { 9b 0b [2] bf 05 [2] 94 29 [2] ba 0b [2] ae 10 [2] a1 0a [2] bf 17 [2] bd 16 [2] a6 10 [2] ba 17 [2] a6 38 }

  condition:
    any of them
}