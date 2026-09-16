rule TTP_XOR_MULT_DOSStub_ec89 {
  strings:
    $key_ec89 = { b8 e1 [2] cc f9 [2] 8b fb [2] cc ea [2] 82 e6 [2] 8e ec [2] 99 e7 [2] 82 a9 [2] bf }

  condition:
    any of them
}