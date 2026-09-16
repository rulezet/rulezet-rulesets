rule TTP_XOR_MULT_DOSStub_cff2 {
  strings:
    $key_cff2 = { 9b 9a [2] ef 82 [2] a8 80 [2] ef 91 [2] a1 9d [2] ad 97 [2] ba 9c [2] a1 d2 [2] 9c }

  condition:
    any of them
}