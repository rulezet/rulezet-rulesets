rule TTP_XOR_MULT_DOSStub_cac0 {
  strings:
    $key_cac0 = { 9e a8 [2] ea b0 [2] ad b2 [2] ea a3 [2] a4 af [2] a8 a5 [2] bf ae [2] a4 e0 [2] 99 }

  condition:
    any of them
}