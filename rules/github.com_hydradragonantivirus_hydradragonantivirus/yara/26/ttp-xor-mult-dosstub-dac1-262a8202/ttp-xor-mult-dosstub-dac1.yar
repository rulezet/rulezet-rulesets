rule TTP_XOR_MULT_DOSStub_dac1 {
  strings:
    $key_dac1 = { 8e a9 [2] fa b1 [2] bd b3 [2] fa a2 [2] b4 ae [2] b8 a4 [2] af af [2] b4 e1 [2] 89 }

  condition:
    any of them
}