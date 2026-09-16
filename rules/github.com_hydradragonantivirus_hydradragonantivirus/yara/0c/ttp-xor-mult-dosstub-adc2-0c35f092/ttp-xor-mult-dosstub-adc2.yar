rule TTP_XOR_MULT_DOSStub_adc2 {
  strings:
    $key_adc2 = { f9 aa [2] 8d b2 [2] ca b0 [2] 8d a1 [2] c3 ad [2] cf a7 [2] d8 ac [2] c3 e2 [2] fe }

  condition:
    any of them
}