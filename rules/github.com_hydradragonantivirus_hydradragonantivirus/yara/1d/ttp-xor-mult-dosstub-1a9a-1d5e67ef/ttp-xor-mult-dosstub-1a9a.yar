rule TTP_XOR_MULT_DOSStub_1a9a {
  strings:
    $key_1a9a = { 4e f2 [2] 3a ea [2] 7d e8 [2] 3a f9 [2] 74 f5 [2] 78 ff [2] 6f f4 [2] 74 ba [2] 49 }

  condition:
    any of them
}