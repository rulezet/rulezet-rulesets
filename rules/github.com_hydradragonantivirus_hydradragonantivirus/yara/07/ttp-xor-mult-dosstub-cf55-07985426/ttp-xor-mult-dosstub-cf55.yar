rule TTP_XOR_MULT_DOSStub_cf55 {
  strings:
    $key_cf55 = { 9b 3d [2] ef 25 [2] a8 27 [2] ef 36 [2] a1 3a [2] ad 30 [2] ba 3b [2] a1 75 [2] 9c }

  condition:
    any of them
}