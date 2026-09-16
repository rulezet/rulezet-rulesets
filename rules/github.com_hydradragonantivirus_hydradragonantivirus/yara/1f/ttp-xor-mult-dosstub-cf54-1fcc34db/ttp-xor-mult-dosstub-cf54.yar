rule TTP_XOR_MULT_DOSStub_cf54 {
  strings:
    $key_cf54 = { 9b 3c [2] ef 24 [2] a8 26 [2] ef 37 [2] a1 3b [2] ad 31 [2] ba 3a [2] a1 74 [2] 9c }

  condition:
    any of them
}