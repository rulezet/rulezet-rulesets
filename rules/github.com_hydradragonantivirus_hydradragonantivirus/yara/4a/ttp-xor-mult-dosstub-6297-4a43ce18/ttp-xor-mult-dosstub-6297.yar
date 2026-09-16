rule TTP_XOR_MULT_DOSStub_6297 {
  strings:
    $key_6297 = { 36 ff [2] 42 e7 [2] 05 e5 [2] 42 f4 [2] 0c f8 [2] 00 f2 [2] 17 f9 [2] 0c b7 [2] 31 }

  condition:
    any of them
}