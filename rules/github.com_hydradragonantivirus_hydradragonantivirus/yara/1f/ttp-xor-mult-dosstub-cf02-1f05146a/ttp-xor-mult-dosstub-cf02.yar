rule TTP_XOR_MULT_DOSStub_cf02 {
  strings:
    $key_cf02 = { 9b 6a [2] ef 72 [2] a8 70 [2] ef 61 [2] a1 6d [2] ad 67 [2] ba 6c [2] a1 22 [2] 9c }

  condition:
    any of them
}