rule TTP_XOR_MULT_DOSStub_2997 {
  strings:
    $key_2997 = { 7d ff [2] 09 e7 [2] 4e e5 [2] 09 f4 [2] 47 f8 [2] 4b f2 [2] 5c f9 [2] 47 b7 [2] 7a }

  condition:
    any of them
}