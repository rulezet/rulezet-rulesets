rule TTP_XOR_MULT_DOSStub_349a {
  strings:
    $key_349a = { 60 f2 [2] 14 ea [2] 53 e8 [2] 14 f9 [2] 5a f5 [2] 56 ff [2] 41 f4 [2] 5a ba [2] 67 }

  condition:
    any of them
}