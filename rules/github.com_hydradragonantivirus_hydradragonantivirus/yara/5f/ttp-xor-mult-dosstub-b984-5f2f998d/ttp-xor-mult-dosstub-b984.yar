rule TTP_XOR_MULT_DOSStub_b984 {
  strings:
    $key_b984 = { ed ec [2] 99 f4 [2] de f6 [2] 99 e7 [2] d7 eb [2] db e1 [2] cc ea [2] d7 a4 [2] ea }

  condition:
    any of them
}