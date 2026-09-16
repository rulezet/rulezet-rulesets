rule TTP_XOR_MULT_DOSStub_089a {
  strings:
    $key_089a = { 5c f2 [2] 28 ea [2] 6f e8 [2] 28 f9 [2] 66 f5 [2] 6a ff [2] 7d f4 [2] 66 ba [2] 5b }

  condition:
    any of them
}