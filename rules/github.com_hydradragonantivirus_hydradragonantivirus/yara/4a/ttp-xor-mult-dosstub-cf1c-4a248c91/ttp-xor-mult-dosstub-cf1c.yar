rule TTP_XOR_MULT_DOSStub_cf1c {
  strings:
    $key_cf1c = { 9b 74 [2] ef 6c [2] a8 6e [2] ef 7f [2] a1 73 [2] ad 79 [2] ba 72 [2] a1 3c [2] 9c }

  condition:
    any of them
}