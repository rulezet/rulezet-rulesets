rule TTP_XOR_MULT_DOSStub_4a8d {
  strings:
    $key_4a8d = { 1e e5 [2] 6a fd [2] 2d ff [2] 6a ee [2] 24 e2 [2] 28 e8 [2] 3f e3 [2] 24 ad [2] 19 }

  condition:
    any of them
}