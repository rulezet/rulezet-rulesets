rule TTP_XOR_MULT_DOSStub_248d {
  strings:
    $key_248d = { 70 e5 [2] 04 fd [2] 43 ff [2] 04 ee [2] 4a e2 [2] 46 e8 [2] 51 e3 [2] 4a ad [2] 77 }

  condition:
    any of them
}