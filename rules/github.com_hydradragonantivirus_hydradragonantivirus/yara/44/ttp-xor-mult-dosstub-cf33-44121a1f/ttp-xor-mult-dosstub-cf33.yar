rule TTP_XOR_MULT_DOSStub_cf33 {
  strings:
    $key_cf33 = { 9b 5b [2] ef 43 [2] a8 41 [2] ef 50 [2] a1 5c [2] ad 56 [2] ba 5d [2] a1 13 [2] 9c }

  condition:
    any of them
}