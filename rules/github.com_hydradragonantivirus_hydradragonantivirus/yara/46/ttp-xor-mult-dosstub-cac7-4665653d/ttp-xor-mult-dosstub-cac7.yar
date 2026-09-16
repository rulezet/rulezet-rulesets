rule TTP_XOR_MULT_DOSStub_cac7 {
  strings:
    $key_cac7 = { 9e af [2] ea b7 [2] ad b5 [2] ea a4 [2] a4 a8 [2] a8 a2 [2] bf a9 [2] a4 e7 [2] 99 }

  condition:
    any of them
}