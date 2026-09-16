rule TTP_XOR_MULT_DOSStub_cf5f {
  strings:
    $key_cf5f = { 9b 37 [2] ef 2f [2] a8 2d [2] ef 3c [2] a1 30 [2] ad 3a [2] ba 31 [2] a1 7f [2] 9c }

  condition:
    any of them
}