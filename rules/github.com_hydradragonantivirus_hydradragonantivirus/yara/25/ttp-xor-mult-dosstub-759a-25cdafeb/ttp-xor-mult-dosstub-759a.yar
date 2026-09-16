rule TTP_XOR_MULT_DOSStub_759a {
  strings:
    $key_759a = { 21 f2 [2] 55 ea [2] 12 e8 [2] 55 f9 [2] 1b f5 [2] 17 ff [2] 00 f4 [2] 1b ba [2] 26 }

  condition:
    any of them
}