rule TTP_XOR_MULT_DOSStub_cfe1 {
  strings:
    $key_cfe1 = { 9b 89 [2] ef 91 [2] a8 93 [2] ef 82 [2] a1 8e [2] ad 84 [2] ba 8f [2] a1 c1 [2] 9c }

  condition:
    any of them
}