rule TTP_XOR_MULT_DOSStub_678d {
  strings:
    $key_678d = { 33 e5 [2] 47 fd [2] 00 ff [2] 47 ee [2] 09 e2 [2] 05 e8 [2] 12 e3 [2] 09 ad [2] 34 }

  condition:
    any of them
}