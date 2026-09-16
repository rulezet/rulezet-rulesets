rule TTP_XOR_MULT_DOSStub_cf59 {
  strings:
    $key_cf59 = { 9b 31 [2] ef 29 [2] a8 2b [2] ef 3a [2] a1 36 [2] ad 3c [2] ba 37 [2] a1 79 [2] 9c }

  condition:
    any of them
}