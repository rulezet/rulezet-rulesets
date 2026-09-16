rule TTP_XOR_MULT_DOSStub_74ca {
  strings:
    $key_74ca = { 20 a2 [2] 54 ba [2] 13 b8 [2] 54 a9 [2] 1a a5 [2] 16 af [2] 01 a4 [2] 1a ea [2] 27 }

  condition:
    any of them
}