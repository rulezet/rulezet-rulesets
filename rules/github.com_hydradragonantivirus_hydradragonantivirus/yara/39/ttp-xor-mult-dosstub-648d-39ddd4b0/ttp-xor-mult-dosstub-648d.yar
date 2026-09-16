rule TTP_XOR_MULT_DOSStub_648d {
  strings:
    $key_648d = { 30 e5 [2] 44 fd [2] 03 ff [2] 44 ee [2] 0a e2 [2] 06 e8 [2] 11 e3 [2] 0a ad [2] 37 }

  condition:
    any of them
}