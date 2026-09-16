rule TTP_XOR_MULT_DOSStub_239a {
  strings:
    $key_239a = { 77 f2 [2] 03 ea [2] 44 e8 [2] 03 f9 [2] 4d f5 [2] 41 ff [2] 56 f4 [2] 4d ba [2] 70 }

  condition:
    any of them
}