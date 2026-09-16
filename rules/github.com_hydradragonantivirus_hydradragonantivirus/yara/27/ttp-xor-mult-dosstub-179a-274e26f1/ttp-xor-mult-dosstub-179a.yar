rule TTP_XOR_MULT_DOSStub_179a {
  strings:
    $key_179a = { 43 f2 [2] 37 ea [2] 70 e8 [2] 37 f9 [2] 79 f5 [2] 75 ff [2] 62 f4 [2] 79 ba [2] 44 }

  condition:
    any of them
}