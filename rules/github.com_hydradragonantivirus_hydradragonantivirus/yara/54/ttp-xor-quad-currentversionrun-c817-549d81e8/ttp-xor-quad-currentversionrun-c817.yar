rule TTP_XOR_QUAD_CurrentVersionRun_c817 {
  strings:
    $key_c817 = { 9b 78 [2] bf 76 [2] 94 5a [2] ba 78 [2] ae 63 [2] a1 79 [2] bf 64 [2] bd 65 [2] a6 63 [2] ba 64 [2] a6 4b }

  condition:
    any of them
}