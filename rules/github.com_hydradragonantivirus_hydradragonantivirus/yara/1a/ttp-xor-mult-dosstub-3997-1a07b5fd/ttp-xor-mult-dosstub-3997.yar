rule TTP_XOR_MULT_DOSStub_3997 {
  strings:
    $key_3997 = { 6d ff [2] 19 e7 [2] 5e e5 [2] 19 f4 [2] 57 f8 [2] 5b f2 [2] 4c f9 [2] 57 b7 [2] 6a }

  condition:
    any of them
}