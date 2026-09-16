rule TTP_XOR_MULT_DOSStub_798d {
  strings:
    $key_798d = { 2d e5 [2] 59 fd [2] 1e ff [2] 59 ee [2] 17 e2 [2] 1b e8 [2] 0c e3 [2] 17 ad [2] 2a }

  condition:
    any of them
}