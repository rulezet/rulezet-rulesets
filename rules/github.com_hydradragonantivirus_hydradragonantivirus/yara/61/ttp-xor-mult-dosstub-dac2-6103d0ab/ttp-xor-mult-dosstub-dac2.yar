rule TTP_XOR_MULT_DOSStub_dac2 {
  strings:
    $key_dac2 = { 8e aa [2] fa b2 [2] bd b0 [2] fa a1 [2] b4 ad [2] b8 a7 [2] af ac [2] b4 e2 [2] 89 }

  condition:
    any of them
}