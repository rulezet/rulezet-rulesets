rule TTP_XOR_MULT_DOSStub_adc1 {
  strings:
    $key_adc1 = { f9 a9 [2] 8d b1 [2] ca b3 [2] 8d a2 [2] c3 ae [2] cf a4 [2] d8 af [2] c3 e1 [2] fe }

  condition:
    any of them
}