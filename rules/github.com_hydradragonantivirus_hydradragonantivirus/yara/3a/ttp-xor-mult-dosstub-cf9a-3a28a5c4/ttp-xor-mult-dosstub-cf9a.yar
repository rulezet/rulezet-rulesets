rule TTP_XOR_MULT_DOSStub_cf9a {
  strings:
    $key_cf9a = { 9b f2 [2] ef ea [2] a8 e8 [2] ef f9 [2] a1 f5 [2] ad ff [2] ba f4 [2] a1 ba [2] 9c }

  condition:
    any of them
}