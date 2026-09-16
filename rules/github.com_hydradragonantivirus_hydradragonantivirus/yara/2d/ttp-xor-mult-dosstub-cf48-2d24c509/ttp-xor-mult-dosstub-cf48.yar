rule TTP_XOR_MULT_DOSStub_cf48 {
  strings:
    $key_cf48 = { 9b 20 [2] ef 38 [2] a8 3a [2] ef 2b [2] a1 27 [2] ad 2d [2] ba 26 [2] a1 68 [2] 9c }

  condition:
    any of them
}