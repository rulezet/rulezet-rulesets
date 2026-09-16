rule TTP_XOR_MULT_DOSStub_cf05 {
  strings:
    $key_cf05 = { 9b 6d [2] ef 75 [2] a8 77 [2] ef 66 [2] a1 6a [2] ad 60 [2] ba 6b [2] a1 25 [2] 9c }

  condition:
    any of them
}