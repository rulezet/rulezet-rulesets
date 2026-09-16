rule TTP_XOR_MULT_DOSStub_3a9a {
  strings:
    $key_3a9a = { 6e f2 [2] 1a ea [2] 5d e8 [2] 1a f9 [2] 54 f5 [2] 58 ff [2] 4f f4 [2] 54 ba [2] 69 }

  condition:
    any of them
}