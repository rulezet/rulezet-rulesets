rule TTP_XOR_MULT_DOSStub_cf34 {
  strings:
    $key_cf34 = { 9b 5c [2] ef 44 [2] a8 46 [2] ef 57 [2] a1 5b [2] ad 51 [2] ba 5a [2] a1 14 [2] 9c }

  condition:
    any of them
}