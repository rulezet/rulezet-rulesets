rule TTP_XOR_MULT_DOSStub_fbd9 {
  strings:
    $key_fbd9 = { af b1 [2] db a9 [2] 9c ab [2] db ba [2] 95 b6 [2] 99 bc [2] 8e b7 [2] 95 f9 [2] a8 }

  condition:
    any of them
}