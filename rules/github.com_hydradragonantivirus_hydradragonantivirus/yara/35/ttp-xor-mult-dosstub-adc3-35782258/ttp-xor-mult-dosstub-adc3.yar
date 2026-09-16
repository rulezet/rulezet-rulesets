rule TTP_XOR_MULT_DOSStub_adc3 {
  strings:
    $key_adc3 = { f9 ab [2] 8d b3 [2] ca b1 [2] 8d a0 [2] c3 ac [2] cf a6 [2] d8 ad [2] c3 e3 [2] fe }

  condition:
    any of them
}