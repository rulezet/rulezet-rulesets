rule TTP_XOR_MULT_DOSStub_cf18 {
  strings:
    $key_cf18 = { 9b 70 [2] ef 68 [2] a8 6a [2] ef 7b [2] a1 77 [2] ad 7d [2] ba 76 [2] a1 38 [2] 9c }

  condition:
    any of them
}