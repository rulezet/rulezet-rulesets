rule TTP_XOR_MULT_DOSStub_cff1 {
  strings:
    $key_cff1 = { 9b 99 [2] ef 81 [2] a8 83 [2] ef 92 [2] a1 9e [2] ad 94 [2] ba 9f [2] a1 d1 [2] 9c }

  condition:
    any of them
}