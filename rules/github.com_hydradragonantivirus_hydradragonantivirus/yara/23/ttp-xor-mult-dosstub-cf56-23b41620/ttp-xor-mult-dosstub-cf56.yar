rule TTP_XOR_MULT_DOSStub_cf56 {
  strings:
    $key_cf56 = { 9b 3e [2] ef 26 [2] a8 24 [2] ef 35 [2] a1 39 [2] ad 33 [2] ba 38 [2] a1 76 [2] 9c }

  condition:
    any of them
}