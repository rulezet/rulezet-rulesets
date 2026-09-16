rule TTP_XOR_MULT_DOSStub_cf4f {
  strings:
    $key_cf4f = { 9b 27 [2] ef 3f [2] a8 3d [2] ef 2c [2] a1 20 [2] ad 2a [2] ba 21 [2] a1 6f [2] 9c }

  condition:
    any of them
}