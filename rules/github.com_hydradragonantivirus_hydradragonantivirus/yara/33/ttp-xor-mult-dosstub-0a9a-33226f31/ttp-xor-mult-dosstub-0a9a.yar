rule TTP_XOR_MULT_DOSStub_0a9a {
  strings:
    $key_0a9a = { 5e f2 [2] 2a ea [2] 6d e8 [2] 2a f9 [2] 64 f5 [2] 68 ff [2] 7f f4 [2] 64 ba [2] 59 }

  condition:
    any of them
}