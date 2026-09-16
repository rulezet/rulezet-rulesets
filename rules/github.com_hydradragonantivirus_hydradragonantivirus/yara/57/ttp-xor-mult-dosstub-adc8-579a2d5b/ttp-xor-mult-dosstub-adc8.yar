rule TTP_XOR_MULT_DOSStub_adc8 {
  strings:
    $key_adc8 = { f9 a0 [2] 8d b8 [2] ca ba [2] 8d ab [2] c3 a7 [2] cf ad [2] d8 a6 [2] c3 e8 [2] fe }

  condition:
    any of them
}