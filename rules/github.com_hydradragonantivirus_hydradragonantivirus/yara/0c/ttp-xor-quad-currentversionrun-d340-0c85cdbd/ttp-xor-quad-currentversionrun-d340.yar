rule TTP_XOR_QUAD_CurrentVersionRun_d340 {
  strings:
    $key_d340 = { 80 2f [2] a4 21 [2] 8f 0d [2] a1 2f [2] b5 34 [2] ba 2e [2] a4 33 [2] a6 32 [2] bd 34 [2] a1 33 [2] bd 1c }

  condition:
    any of them
}