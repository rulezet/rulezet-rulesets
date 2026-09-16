rule TTP_XOR_MULT_DOSStub_cf88 {
  strings:
    $key_cf88 = { 9b e0 [2] ef f8 [2] a8 fa [2] ef eb [2] a1 e7 [2] ad ed [2] ba e6 [2] a1 a8 [2] 9c }

  condition:
    any of them
}