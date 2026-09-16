rule TTP_XOR_MULT_DOSStub_108d {
  strings:
    $key_108d = { 44 e5 [2] 30 fd [2] 77 ff [2] 30 ee [2] 7e e2 [2] 72 e8 [2] 65 e3 [2] 7e ad [2] 43 }

  condition:
    any of them
}