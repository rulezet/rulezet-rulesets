rule TTP_XOR_QUAD_CurrentVersionRun_c82b {
  strings:
    $key_c82b = { 9b 44 [2] bf 4a [2] 94 66 [2] ba 44 [2] ae 5f [2] a1 45 [2] bf 58 [2] bd 59 [2] a6 5f [2] ba 58 [2] a6 77 }

  condition:
    any of them
}