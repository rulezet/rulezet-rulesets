rule TTP_XOR_MULT_DOSStub_44ca {
  strings:
    $key_44ca = { 10 a2 [2] 64 ba [2] 23 b8 [2] 64 a9 [2] 2a a5 [2] 26 af [2] 31 a4 [2] 2a ea [2] 17 }

  condition:
    any of them
}