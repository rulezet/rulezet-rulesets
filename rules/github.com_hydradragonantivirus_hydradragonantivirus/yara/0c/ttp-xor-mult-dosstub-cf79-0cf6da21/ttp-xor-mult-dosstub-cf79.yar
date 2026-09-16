rule TTP_XOR_MULT_DOSStub_cf79 {
  strings:
    $key_cf79 = { 9b 11 [2] ef 09 [2] a8 0b [2] ef 1a [2] a1 16 [2] ad 1c [2] ba 17 [2] a1 59 [2] 9c }

  condition:
    any of them
}