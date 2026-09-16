rule TTP_XOR_MULT_DOSStub_1997 {
  strings:
    $key_1997 = { 4d ff [2] 39 e7 [2] 7e e5 [2] 39 f4 [2] 77 f8 [2] 7b f2 [2] 6c f9 [2] 77 b7 [2] 4a }

  condition:
    any of them
}