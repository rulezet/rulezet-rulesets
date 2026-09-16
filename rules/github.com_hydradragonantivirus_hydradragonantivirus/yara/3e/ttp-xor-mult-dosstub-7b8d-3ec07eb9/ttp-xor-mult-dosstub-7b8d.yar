rule TTP_XOR_MULT_DOSStub_7b8d {
  strings:
    $key_7b8d = { 2f e5 [2] 5b fd [2] 1c ff [2] 5b ee [2] 15 e2 [2] 19 e8 [2] 0e e3 [2] 15 ad [2] 28 }

  condition:
    any of them
}