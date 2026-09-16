rule TTP_XOR_MULT_DOSStub_d356 {
  strings:
    $key_d356 = { 87 3e [2] f3 26 [2] b4 24 [2] f3 35 [2] bd 39 [2] b1 33 [2] a6 38 [2] bd 76 [2] 80 }

  condition:
    any of them
}