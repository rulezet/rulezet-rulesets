rule TTP_XOR_MULT_DOSStub_fbd6 {
  strings:
    $key_fbd6 = { af be [2] db a6 [2] 9c a4 [2] db b5 [2] 95 b9 [2] 99 b3 [2] 8e b8 [2] 95 f6 [2] a8 }

  condition:
    any of them
}