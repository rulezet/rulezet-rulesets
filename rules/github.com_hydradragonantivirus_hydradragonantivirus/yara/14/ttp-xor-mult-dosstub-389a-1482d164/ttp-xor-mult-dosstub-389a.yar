rule TTP_XOR_MULT_DOSStub_389a {
  strings:
    $key_389a = { 6c f2 [2] 18 ea [2] 5f e8 [2] 18 f9 [2] 56 f5 [2] 5a ff [2] 4d f4 [2] 56 ba [2] 6b }

  condition:
    any of them
}