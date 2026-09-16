rule TTP_XOR_MULT_DOSStub_cf31 {
  strings:
    $key_cf31 = { 9b 59 [2] ef 41 [2] a8 43 [2] ef 52 [2] a1 5e [2] ad 54 [2] ba 5f [2] a1 11 [2] 9c }

  condition:
    any of them
}