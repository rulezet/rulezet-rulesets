rule TTP_XOR_MULT_DOSStub_ca84 {
  strings:
    $key_ca84 = { 9e ec [2] ea f4 [2] ad f6 [2] ea e7 [2] a4 eb [2] a8 e1 [2] bf ea [2] a4 a4 [2] 99 }

  condition:
    any of them
}