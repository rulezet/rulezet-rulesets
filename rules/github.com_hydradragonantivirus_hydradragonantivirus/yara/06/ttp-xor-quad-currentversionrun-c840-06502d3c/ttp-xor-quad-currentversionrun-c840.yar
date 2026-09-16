rule TTP_XOR_QUAD_CurrentVersionRun_c840 {
  strings:
    $key_c840 = { 9b 2f [2] bf 21 [2] 94 0d [2] ba 2f [2] ae 34 [2] a1 2e [2] bf 33 [2] bd 32 [2] a6 34 [2] ba 33 [2] a6 1c }

  condition:
    any of them
}