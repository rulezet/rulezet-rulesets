rule TTP_XOR_MULT_DOSStub_689a {
  strings:
    $key_689a = { 3c f2 [2] 48 ea [2] 0f e8 [2] 48 f9 [2] 06 f5 [2] 0a ff [2] 1d f4 [2] 06 ba [2] 3b }

  condition:
    any of them
}