rule TTP_XOR_MULT_DOSStub_399a {
  strings:
    $key_399a = { 6d f2 [2] 19 ea [2] 5e e8 [2] 19 f9 [2] 57 f5 [2] 5b ff [2] 4c f4 [2] 57 ba [2] 6a }

  condition:
    any of them
}