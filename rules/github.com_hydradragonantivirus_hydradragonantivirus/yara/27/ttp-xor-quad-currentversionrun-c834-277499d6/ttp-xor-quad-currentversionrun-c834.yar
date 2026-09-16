rule TTP_XOR_QUAD_CurrentVersionRun_c834 {
  strings:
    $key_c834 = { 9b 5b [2] bf 55 [2] 94 79 [2] ba 5b [2] ae 40 [2] a1 5a [2] bf 47 [2] bd 46 [2] a6 40 [2] ba 47 [2] a6 68 }

  condition:
    any of them
}