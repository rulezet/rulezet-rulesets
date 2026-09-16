rule TTP_XOR_MULT_DOSStub_cf0d {
  strings:
    $key_cf0d = { 9b 65 [2] ef 7d [2] a8 7f [2] ef 6e [2] a1 62 [2] ad 68 [2] ba 63 [2] a1 2d [2] 9c }

  condition:
    any of them
}