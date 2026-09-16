rule TTP_XOR_MULT_DOSStub_d336 {
  strings:
    $key_d336 = { 87 5e [2] f3 46 [2] b4 44 [2] f3 55 [2] bd 59 [2] b1 53 [2] a6 58 [2] bd 16 [2] 80 }

  condition:
    any of them
}