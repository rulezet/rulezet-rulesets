rule TTP_XOR_QUAD_CurrentVersionRun_c872 {
  strings:
    $key_c872 = { 9b 1d [2] bf 13 [2] 94 3f [2] ba 1d [2] ae 06 [2] a1 1c [2] bf 01 [2] bd 00 [2] a6 06 [2] ba 01 [2] a6 2e }

  condition:
    any of them
}