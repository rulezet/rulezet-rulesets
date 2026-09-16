rule TTP_XOR_MULT_DOSStub_cf16 {
  strings:
    $key_cf16 = { 9b 7e [2] ef 66 [2] a8 64 [2] ef 75 [2] a1 79 [2] ad 73 [2] ba 78 [2] a1 36 [2] 9c }

  condition:
    any of them
}