rule TTP_XOR_QUAD_CurrentVersionRun_c859 {
  strings:
    $key_c859 = { 9b 36 [2] bf 38 [2] 94 14 [2] ba 36 [2] ae 2d [2] a1 37 [2] bf 2a [2] bd 2b [2] a6 2d [2] ba 2a [2] a6 05 }

  condition:
    any of them
}