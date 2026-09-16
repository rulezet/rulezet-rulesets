rule TTP_XOR_QUAD_CurrentVersionRun_d336 {
  strings:
    $key_d336 = { 80 59 [2] a4 57 [2] 8f 7b [2] a1 59 [2] b5 42 [2] ba 58 [2] a4 45 [2] a6 44 [2] bd 42 [2] a1 45 [2] bd 6a }

  condition:
    any of them
}