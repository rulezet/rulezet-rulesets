rule TTP_XOR_MULT_DOSStub_d347 {
  strings:
    $key_d347 = { 87 2f [2] f3 37 [2] b4 35 [2] f3 24 [2] bd 28 [2] b1 22 [2] a6 29 [2] bd 67 [2] 80 }

  condition:
    any of them
}