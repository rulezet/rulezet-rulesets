rule TTP_XOR_MULT_DOSStub_adcb {
  strings:
    $key_adcb = { f9 a3 [2] 8d bb [2] ca b9 [2] 8d a8 [2] c3 a4 [2] cf ae [2] d8 a5 [2] c3 eb [2] fe }

  condition:
    any of them
}