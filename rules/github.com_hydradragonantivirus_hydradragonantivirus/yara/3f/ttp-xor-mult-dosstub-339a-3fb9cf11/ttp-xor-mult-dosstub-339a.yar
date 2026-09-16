rule TTP_XOR_MULT_DOSStub_339a {
  strings:
    $key_339a = { 67 f2 [2] 13 ea [2] 54 e8 [2] 13 f9 [2] 5d f5 [2] 51 ff [2] 46 f4 [2] 5d ba [2] 60 }

  condition:
    any of them
}