rule TTP_XOR_QUAD_CurrentVersionRun_c8f5 {
  strings:
    $key_c8f5 = { 9b 9a [2] bf 94 [2] 94 b8 [2] ba 9a [2] ae 81 [2] a1 9b [2] bf 86 [2] bd 87 [2] a6 81 [2] ba 86 [2] a6 a9 }

  condition:
    any of them
}