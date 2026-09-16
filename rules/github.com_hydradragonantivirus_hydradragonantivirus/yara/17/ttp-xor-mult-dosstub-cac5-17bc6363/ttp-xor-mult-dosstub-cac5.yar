rule TTP_XOR_MULT_DOSStub_cac5 {
  strings:
    $key_cac5 = { 9e ad [2] ea b5 [2] ad b7 [2] ea a6 [2] a4 aa [2] a8 a0 [2] bf ab [2] a4 e5 [2] 99 }

  condition:
    any of them
}