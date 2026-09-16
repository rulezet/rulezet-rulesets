rule TTP_XOR_MULT_DOSStub_cf65 {
  strings:
    $key_cf65 = { 9b 0d [2] ef 15 [2] a8 17 [2] ef 06 [2] a1 0a [2] ad 00 [2] ba 0b [2] a1 45 [2] 9c }

  condition:
    any of them
}