rule TTP_XOR_MULT_DOSStub_7a8d {
  strings:
    $key_7a8d = { 2e e5 [2] 5a fd [2] 1d ff [2] 5a ee [2] 14 e2 [2] 18 e8 [2] 0f e3 [2] 14 ad [2] 29 }

  condition:
    any of them
}