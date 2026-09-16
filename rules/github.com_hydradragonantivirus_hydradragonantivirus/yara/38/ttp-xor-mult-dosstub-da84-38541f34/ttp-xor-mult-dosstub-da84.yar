rule TTP_XOR_MULT_DOSStub_da84 {
  strings:
    $key_da84 = { 8e ec [2] fa f4 [2] bd f6 [2] fa e7 [2] b4 eb [2] b8 e1 [2] af ea [2] b4 a4 [2] 89 }

  condition:
    any of them
}