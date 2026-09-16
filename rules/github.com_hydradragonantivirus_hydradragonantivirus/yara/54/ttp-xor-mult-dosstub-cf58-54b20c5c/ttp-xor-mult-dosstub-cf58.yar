rule TTP_XOR_MULT_DOSStub_cf58 {
  strings:
    $key_cf58 = { 9b 30 [2] ef 28 [2] a8 2a [2] ef 3b [2] a1 37 [2] ad 3d [2] ba 36 [2] a1 78 [2] 9c }

  condition:
    any of them
}