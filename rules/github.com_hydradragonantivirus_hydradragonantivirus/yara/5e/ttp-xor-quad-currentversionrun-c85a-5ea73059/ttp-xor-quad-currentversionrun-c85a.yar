rule TTP_XOR_QUAD_CurrentVersionRun_c85a {
  strings:
    $key_c85a = { 9b 35 [2] bf 3b [2] 94 17 [2] ba 35 [2] ae 2e [2] a1 34 [2] bf 29 [2] bd 28 [2] a6 2e [2] ba 29 [2] a6 06 }

  condition:
    any of them
}