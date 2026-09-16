rule TTP_XOR_MULT_DOSStub_adc0 {
  strings:
    $key_adc0 = { f9 a8 [2] 8d b0 [2] ca b2 [2] 8d a3 [2] c3 af [2] cf a5 [2] d8 ae [2] c3 e0 [2] fe }

  condition:
    any of them
}