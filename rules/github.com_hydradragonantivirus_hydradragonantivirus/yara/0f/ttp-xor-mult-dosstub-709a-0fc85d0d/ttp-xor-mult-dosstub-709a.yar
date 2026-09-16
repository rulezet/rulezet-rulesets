rule TTP_XOR_MULT_DOSStub_709a {
  strings:
    $key_709a = { 24 f2 [2] 50 ea [2] 17 e8 [2] 50 f9 [2] 1e f5 [2] 12 ff [2] 05 f4 [2] 1e ba [2] 23 }

  condition:
    any of them
}