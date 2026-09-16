rule TTP_XOR_MULT_DOSStub_cac4 {
  strings:
    $key_cac4 = { 9e ac [2] ea b4 [2] ad b6 [2] ea a7 [2] a4 ab [2] a8 a1 [2] bf aa [2] a4 e4 [2] 99 }

  condition:
    any of them
}