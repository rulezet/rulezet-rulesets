rule TTP_XOR_MULT_DOSStub_468d {
  strings:
    $key_468d = { 12 e5 [2] 66 fd [2] 21 ff [2] 66 ee [2] 28 e2 [2] 24 e8 [2] 33 e3 [2] 28 ad [2] 15 }

  condition:
    any of them
}