rule TTP_XOR_MULT_DOSStub_329a {
  strings:
    $key_329a = { 66 f2 [2] 12 ea [2] 55 e8 [2] 12 f9 [2] 5c f5 [2] 50 ff [2] 47 f4 [2] 5c ba [2] 61 }

  condition:
    any of them
}