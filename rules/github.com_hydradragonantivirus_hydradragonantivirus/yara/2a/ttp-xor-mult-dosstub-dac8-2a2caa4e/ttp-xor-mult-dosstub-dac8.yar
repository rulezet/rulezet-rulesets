rule TTP_XOR_MULT_DOSStub_dac8 {
  strings:
    $key_dac8 = { 8e a0 [2] fa b8 [2] bd ba [2] fa ab [2] b4 a7 [2] b8 ad [2] af a6 [2] b4 e8 [2] 89 }

  condition:
    any of them
}