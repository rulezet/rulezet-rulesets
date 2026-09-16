rule TTP_XOR_QUAD_CurrentVersionRun_c822 {
  strings:
    $key_c822 = { 9b 4d [2] bf 43 [2] 94 6f [2] ba 4d [2] ae 56 [2] a1 4c [2] bf 51 [2] bd 50 [2] a6 56 [2] ba 51 [2] a6 7e }

  condition:
    any of them
}