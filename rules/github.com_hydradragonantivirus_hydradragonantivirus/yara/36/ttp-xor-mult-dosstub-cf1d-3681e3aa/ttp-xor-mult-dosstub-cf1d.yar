rule TTP_XOR_MULT_DOSStub_cf1d {
  strings:
    $key_cf1d = { 9b 75 [2] ef 6d [2] a8 6f [2] ef 7e [2] a1 72 [2] ad 78 [2] ba 73 [2] a1 3d [2] 9c }

  condition:
    any of them
}