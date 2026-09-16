rule TTP_XOR_MULT_DOSStub_04ca {
  strings:
    $key_04ca = { 50 a2 [2] 24 ba [2] 63 b8 [2] 24 a9 [2] 6a a5 [2] 66 af [2] 71 a4 [2] 6a ea [2] 57 }

  condition:
    any of them
}