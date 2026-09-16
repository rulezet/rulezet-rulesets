rule TTP_XOR_MULT_DOSStub_7997 {
  strings:
    $key_7997 = { 2d ff [2] 59 e7 [2] 1e e5 [2] 59 f4 [2] 17 f8 [2] 1b f2 [2] 0c f9 [2] 17 b7 [2] 2a }

  condition:
    any of them
}