rule TTP_XOR_MULT_DOSStub_fbc1 {
  strings:
    $key_fbc1 = { af a9 [2] db b1 [2] 9c b3 [2] db a2 [2] 95 ae [2] 99 a4 [2] 8e af [2] 95 e1 [2] a8 }

  condition:
    any of them
}