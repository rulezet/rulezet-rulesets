rule TTP_XOR_MULT_DOSStub_14ca {
  strings:
    $key_14ca = { 40 a2 [2] 34 ba [2] 73 b8 [2] 34 a9 [2] 7a a5 [2] 76 af [2] 61 a4 [2] 7a ea [2] 47 }

  condition:
    any of them
}