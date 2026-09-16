rule TTP_XOR_QUAD_CurrentVersionRun_c830 {
  strings:
    $key_c830 = { 9b 5f [2] bf 51 [2] 94 7d [2] ba 5f [2] ae 44 [2] a1 5e [2] bf 43 [2] bd 42 [2] a6 44 [2] ba 43 [2] a6 6c }

  condition:
    any of them
}