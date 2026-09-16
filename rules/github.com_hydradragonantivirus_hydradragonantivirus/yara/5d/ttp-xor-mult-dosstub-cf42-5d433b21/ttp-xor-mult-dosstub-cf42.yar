rule TTP_XOR_MULT_DOSStub_cf42 {
  strings:
    $key_cf42 = { 9b 2a [2] ef 32 [2] a8 30 [2] ef 21 [2] a1 2d [2] ad 27 [2] ba 2c [2] a1 62 [2] 9c }

  condition:
    any of them
}