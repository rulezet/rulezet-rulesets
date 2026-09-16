rule TTP_XOR_MULT_DOSStub_428d {
  strings:
    $key_428d = { 16 e5 [2] 62 fd [2] 25 ff [2] 62 ee [2] 2c e2 [2] 20 e8 [2] 37 e3 [2] 2c ad [2] 11 }

  condition:
    any of them
}