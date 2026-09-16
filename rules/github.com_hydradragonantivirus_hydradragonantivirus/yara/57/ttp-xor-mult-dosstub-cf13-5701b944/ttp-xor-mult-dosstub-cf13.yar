rule TTP_XOR_MULT_DOSStub_cf13 {
  strings:
    $key_cf13 = { 9b 7b [2] ef 63 [2] a8 61 [2] ef 70 [2] a1 7c [2] ad 76 [2] ba 7d [2] a1 33 [2] 9c }

  condition:
    any of them
}