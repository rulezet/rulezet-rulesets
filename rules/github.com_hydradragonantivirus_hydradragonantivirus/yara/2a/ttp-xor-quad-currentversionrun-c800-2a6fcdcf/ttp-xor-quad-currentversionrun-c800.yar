rule TTP_XOR_QUAD_CurrentVersionRun_c800 {
  strings:
    $key_c800 = { 9b 6f [2] bf 61 [2] 94 4d [2] ba 6f [2] ae 74 [2] a1 6e [2] bf 73 [2] bd 72 [2] a6 74 [2] ba 73 [2] a6 5c }

  condition:
    any of them
}