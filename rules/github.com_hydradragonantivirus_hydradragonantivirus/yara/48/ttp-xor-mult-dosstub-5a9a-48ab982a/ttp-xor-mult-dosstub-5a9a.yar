rule TTP_XOR_MULT_DOSStub_5a9a {
  strings:
    $key_5a9a = { 0e f2 [2] 7a ea [2] 3d e8 [2] 7a f9 [2] 34 f5 [2] 38 ff [2] 2f f4 [2] 34 ba [2] 09 }

  condition:
    any of them
}