rule TTP_XOR_MULT_DOSStub_599a {
  strings:
    $key_599a = { 0d f2 [2] 79 ea [2] 3e e8 [2] 79 f9 [2] 37 f5 [2] 3b ff [2] 2c f4 [2] 37 ba [2] 0a }

  condition:
    any of them
}