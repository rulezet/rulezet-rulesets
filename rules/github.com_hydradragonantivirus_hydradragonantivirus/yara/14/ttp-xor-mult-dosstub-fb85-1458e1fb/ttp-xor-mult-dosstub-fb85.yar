rule TTP_XOR_MULT_DOSStub_fb85 {
  strings:
    $key_fb85 = { af ed [2] db f5 [2] 9c f7 [2] db e6 [2] 95 ea [2] 99 e0 [2] 8e eb [2] 95 a5 [2] a8 }

  condition:
    any of them
}