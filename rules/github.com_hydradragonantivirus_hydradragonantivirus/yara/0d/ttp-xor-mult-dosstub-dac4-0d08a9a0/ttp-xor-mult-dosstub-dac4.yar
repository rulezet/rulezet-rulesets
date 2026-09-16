rule TTP_XOR_MULT_DOSStub_dac4 {
  strings:
    $key_dac4 = { 8e ac [2] fa b4 [2] bd b6 [2] fa a7 [2] b4 ab [2] b8 a1 [2] af aa [2] b4 e4 [2] 89 }

  condition:
    any of them
}