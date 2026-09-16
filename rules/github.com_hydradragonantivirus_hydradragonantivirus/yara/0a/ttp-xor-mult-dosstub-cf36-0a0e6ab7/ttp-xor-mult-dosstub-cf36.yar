rule TTP_XOR_MULT_DOSStub_cf36 {
  strings:
    $key_cf36 = { 9b 5e [2] ef 46 [2] a8 44 [2] ef 55 [2] a1 59 [2] ad 53 [2] ba 58 [2] a1 16 [2] 9c }

  condition:
    any of them
}