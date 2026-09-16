rule TTP_XOR_MULT_DOSStub_478d {
  strings:
    $key_478d = { 13 e5 [2] 67 fd [2] 20 ff [2] 67 ee [2] 29 e2 [2] 25 e8 [2] 32 e3 [2] 29 ad [2] 14 }

  condition:
    any of them
}