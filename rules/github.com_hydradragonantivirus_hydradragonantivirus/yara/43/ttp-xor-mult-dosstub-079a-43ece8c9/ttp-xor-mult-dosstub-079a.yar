rule TTP_XOR_MULT_DOSStub_079a {
  strings:
    $key_079a = { 53 f2 [2] 27 ea [2] 60 e8 [2] 27 f9 [2] 69 f5 [2] 65 ff [2] 72 f4 [2] 69 ba [2] 54 }

  condition:
    any of them
}