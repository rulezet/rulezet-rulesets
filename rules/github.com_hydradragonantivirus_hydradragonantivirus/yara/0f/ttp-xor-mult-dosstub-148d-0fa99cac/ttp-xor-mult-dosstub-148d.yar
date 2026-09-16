rule TTP_XOR_MULT_DOSStub_148d {
  strings:
    $key_148d = { 40 e5 [2] 34 fd [2] 73 ff [2] 34 ee [2] 7a e2 [2] 76 e8 [2] 61 e3 [2] 7a ad [2] 47 }

  condition:
    any of them
}