rule TTP_XOR_QUAD_CurrentVersionRun_c813 {
  strings:
    $key_c813 = { 9b 7c [2] bf 72 [2] 94 5e [2] ba 7c [2] ae 67 [2] a1 7d [2] bf 60 [2] bd 61 [2] a6 67 [2] ba 60 [2] a6 4f }

  condition:
    any of them
}