rule TTP_XOR_MULT_DOSStub_189a {
  strings:
    $key_189a = { 4c f2 [2] 38 ea [2] 7f e8 [2] 38 f9 [2] 76 f5 [2] 7a ff [2] 6d f4 [2] 76 ba [2] 4b }

  condition:
    any of them
}