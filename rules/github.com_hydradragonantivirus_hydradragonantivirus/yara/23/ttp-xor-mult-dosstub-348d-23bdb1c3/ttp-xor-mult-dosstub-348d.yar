rule TTP_XOR_MULT_DOSStub_348d {
  strings:
    $key_348d = { 60 e5 [2] 14 fd [2] 53 ff [2] 14 ee [2] 5a e2 [2] 56 e8 [2] 41 e3 [2] 5a ad [2] 67 }

  condition:
    any of them
}