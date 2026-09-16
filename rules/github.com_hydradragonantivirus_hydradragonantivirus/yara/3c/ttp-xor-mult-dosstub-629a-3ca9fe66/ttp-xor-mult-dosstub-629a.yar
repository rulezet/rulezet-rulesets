rule TTP_XOR_MULT_DOSStub_629a {
  strings:
    $key_629a = { 36 f2 [2] 42 ea [2] 05 e8 [2] 42 f9 [2] 0c f5 [2] 00 ff [2] 17 f4 [2] 0c ba [2] 31 }

  condition:
    any of them
}