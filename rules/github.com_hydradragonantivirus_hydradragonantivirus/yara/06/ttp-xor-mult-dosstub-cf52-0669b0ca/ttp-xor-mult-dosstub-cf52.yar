rule TTP_XOR_MULT_DOSStub_cf52 {
  strings:
    $key_cf52 = { 9b 3a [2] ef 22 [2] a8 20 [2] ef 31 [2] a1 3d [2] ad 37 [2] ba 3c [2] a1 72 [2] 9c }

  condition:
    any of them
}