rule TTP_XOR_MULT_DOSStub_cf17 {
  strings:
    $key_cf17 = { 9b 7f [2] ef 67 [2] a8 65 [2] ef 74 [2] a1 78 [2] ad 72 [2] ba 79 [2] a1 37 [2] 9c }

  condition:
    any of them
}