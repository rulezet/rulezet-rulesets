rule TTP_XOR_MULT_DOSStub_cf2d {
  strings:
    $key_cf2d = { 9b 45 [2] ef 5d [2] a8 5f [2] ef 4e [2] a1 42 [2] ad 48 [2] ba 43 [2] a1 0d [2] 9c }

  condition:
    any of them
}