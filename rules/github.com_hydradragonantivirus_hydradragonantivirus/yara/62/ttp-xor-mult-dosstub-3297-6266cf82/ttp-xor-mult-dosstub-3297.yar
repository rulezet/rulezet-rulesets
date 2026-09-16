rule TTP_XOR_MULT_DOSStub_3297 {
  strings:
    $key_3297 = { 66 ff [2] 12 e7 [2] 55 e5 [2] 12 f4 [2] 5c f8 [2] 50 f2 [2] 47 f9 [2] 5c b7 [2] 61 }

  condition:
    any of them
}