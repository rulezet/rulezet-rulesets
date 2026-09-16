rule TTP_XOR_MULT_DOSStub_cac3 {
  strings:
    $key_cac3 = { 9e ab [2] ea b3 [2] ad b1 [2] ea a0 [2] a4 ac [2] a8 a6 [2] bf ad [2] a4 e3 [2] 99 }

  condition:
    any of them
}