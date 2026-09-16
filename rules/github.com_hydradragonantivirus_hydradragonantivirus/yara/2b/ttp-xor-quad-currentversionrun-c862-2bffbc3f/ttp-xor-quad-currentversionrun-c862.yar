rule TTP_XOR_QUAD_CurrentVersionRun_c862 {
  strings:
    $key_c862 = { 9b 0d [2] bf 03 [2] 94 2f [2] ba 0d [2] ae 16 [2] a1 0c [2] bf 11 [2] bd 10 [2] a6 16 [2] ba 11 [2] a6 3e }

  condition:
    any of them
}