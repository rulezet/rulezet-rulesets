rule TTP_XOR_MULT_DOSStub_cf3d {
  strings:
    $key_cf3d = { 9b 55 [2] ef 4d [2] a8 4f [2] ef 5e [2] a1 52 [2] ad 58 [2] ba 53 [2] a1 1d [2] 9c }

  condition:
    any of them
}