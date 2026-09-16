rule TTP_XOR_MULT_DOSStub_dac0 {
  strings:
    $key_dac0 = { 8e a8 [2] fa b0 [2] bd b2 [2] fa a3 [2] b4 af [2] b8 a5 [2] af ae [2] b4 e0 [2] 89 }

  condition:
    any of them
}