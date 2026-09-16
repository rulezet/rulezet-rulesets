rule TTP_XOR_MULT_DOSStub_fbc4 {
  strings:
    $key_fbc4 = { af ac [2] db b4 [2] 9c b6 [2] db a7 [2] 95 ab [2] 99 a1 [2] 8e aa [2] 95 e4 [2] a8 }

  condition:
    any of them
}