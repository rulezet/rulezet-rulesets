rule TTP_XOR_MULT_DOSStub_099a {
  strings:
    $key_099a = { 5d f2 [2] 29 ea [2] 6e e8 [2] 29 f9 [2] 67 f5 [2] 6b ff [2] 7c f4 [2] 67 ba [2] 5a }

  condition:
    any of them
}