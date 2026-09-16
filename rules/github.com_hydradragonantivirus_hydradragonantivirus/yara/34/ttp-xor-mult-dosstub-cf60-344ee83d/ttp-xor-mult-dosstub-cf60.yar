rule TTP_XOR_MULT_DOSStub_cf60 {
  strings:
    $key_cf60 = { 9b 08 [2] ef 10 [2] a8 12 [2] ef 03 [2] a1 0f [2] ad 05 [2] ba 0e [2] a1 40 [2] 9c }

  condition:
    any of them
}