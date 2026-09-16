rule TTP_XOR_MULT_DOSStub_64ca {
  strings:
    $key_64ca = { 30 a2 [2] 44 ba [2] 03 b8 [2] 44 a9 [2] 0a a5 [2] 06 af [2] 11 a4 [2] 0a ea [2] 37 }

  condition:
    any of them
}