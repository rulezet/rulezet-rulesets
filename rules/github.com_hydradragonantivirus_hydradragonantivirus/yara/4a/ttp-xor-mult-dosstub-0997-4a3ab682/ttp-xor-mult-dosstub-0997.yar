rule TTP_XOR_MULT_DOSStub_0997 {
  strings:
    $key_0997 = { 5d ff [2] 29 e7 [2] 6e e5 [2] 29 f4 [2] 67 f8 [2] 6b f2 [2] 7c f9 [2] 67 b7 [2] 5a }

  condition:
    any of them
}