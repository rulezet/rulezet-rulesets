rule TTP_XOR_MULT_DOSStub_cac1 {
  strings:
    $key_cac1 = { 9e a9 [2] ea b1 [2] ad b3 [2] ea a2 [2] a4 ae [2] a8 a4 [2] bf af [2] a4 e1 [2] 99 }

  condition:
    any of them
}