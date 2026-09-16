rule TTP_XOR_MULT_DOSStub_cf5a {
  strings:
    $key_cf5a = { 9b 32 [2] ef 2a [2] a8 28 [2] ef 39 [2] a1 35 [2] ad 3f [2] ba 34 [2] a1 7a [2] 9c }

  condition:
    any of them
}