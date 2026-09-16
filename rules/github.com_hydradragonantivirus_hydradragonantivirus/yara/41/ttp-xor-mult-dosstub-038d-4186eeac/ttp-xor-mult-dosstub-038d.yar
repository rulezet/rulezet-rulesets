rule TTP_XOR_MULT_DOSStub_038d {
  strings:
    $key_038d = { 57 e5 [2] 23 fd [2] 64 ff [2] 23 ee [2] 6d e2 [2] 61 e8 [2] 76 e3 [2] 6d ad [2] 50 }

  condition:
    any of them
}