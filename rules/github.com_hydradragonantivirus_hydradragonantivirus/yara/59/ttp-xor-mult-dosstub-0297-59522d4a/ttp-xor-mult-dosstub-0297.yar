rule TTP_XOR_MULT_DOSStub_0297 {
  strings:
    $key_0297 = { 56 ff [2] 22 e7 [2] 65 e5 [2] 22 f4 [2] 6c f8 [2] 60 f2 [2] 77 f9 [2] 6c b7 [2] 51 }

  condition:
    any of them
}