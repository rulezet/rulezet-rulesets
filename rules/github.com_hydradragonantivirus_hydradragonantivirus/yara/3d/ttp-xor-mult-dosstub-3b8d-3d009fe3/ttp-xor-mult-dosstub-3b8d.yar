rule TTP_XOR_MULT_DOSStub_3b8d {
  strings:
    $key_3b8d = { 6f e5 [2] 1b fd [2] 5c ff [2] 1b ee [2] 55 e2 [2] 59 e8 [2] 4e e3 [2] 55 ad [2] 68 }

  condition:
    any of them
}