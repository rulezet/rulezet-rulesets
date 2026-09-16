rule TTP_XOR_QUAD_CurrentVersionRun_c836 {
  strings:
    $key_c836 = { 9b 59 [2] bf 57 [2] 94 7b [2] ba 59 [2] ae 42 [2] a1 58 [2] bf 45 [2] bd 44 [2] a6 42 [2] ba 45 [2] a6 6a }

  condition:
    any of them
}