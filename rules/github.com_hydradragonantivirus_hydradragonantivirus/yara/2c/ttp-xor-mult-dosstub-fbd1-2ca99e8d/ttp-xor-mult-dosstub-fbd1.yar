rule TTP_XOR_MULT_DOSStub_fbd1 {
  strings:
    $key_fbd1 = { af b9 [2] db a1 [2] 9c a3 [2] db b2 [2] 95 be [2] 99 b4 [2] 8e bf [2] 95 f1 [2] a8 }

  condition:
    any of them
}