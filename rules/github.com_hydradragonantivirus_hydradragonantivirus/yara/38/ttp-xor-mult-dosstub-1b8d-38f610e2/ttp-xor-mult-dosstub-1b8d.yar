rule TTP_XOR_MULT_DOSStub_1b8d {
  strings:
    $key_1b8d = { 4f e5 [2] 3b fd [2] 7c ff [2] 3b ee [2] 75 e2 [2] 79 e8 [2] 6e e3 [2] 75 ad [2] 48 }

  condition:
    any of them
}