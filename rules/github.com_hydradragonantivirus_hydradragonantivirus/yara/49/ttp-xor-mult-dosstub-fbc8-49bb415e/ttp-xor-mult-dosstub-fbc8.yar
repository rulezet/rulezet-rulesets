rule TTP_XOR_MULT_DOSStub_fbc8 {
  strings:
    $key_fbc8 = { af a0 [2] db b8 [2] 9c ba [2] db ab [2] 95 a7 [2] 99 ad [2] 8e a6 [2] 95 e8 [2] a8 }

  condition:
    any of them
}