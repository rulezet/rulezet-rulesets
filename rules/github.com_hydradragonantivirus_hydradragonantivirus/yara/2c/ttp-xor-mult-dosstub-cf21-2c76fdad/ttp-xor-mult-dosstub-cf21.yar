rule TTP_XOR_MULT_DOSStub_cf21 {
  strings:
    $key_cf21 = { 9b 49 [2] ef 51 [2] a8 53 [2] ef 42 [2] a1 4e [2] ad 44 [2] ba 4f [2] a1 01 [2] 9c }

  condition:
    any of them
}