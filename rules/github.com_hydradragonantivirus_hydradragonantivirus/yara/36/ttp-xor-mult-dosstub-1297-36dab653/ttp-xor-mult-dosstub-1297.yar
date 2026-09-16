rule TTP_XOR_MULT_DOSStub_1297 {
  strings:
    $key_1297 = { 46 ff [2] 32 e7 [2] 75 e5 [2] 32 f4 [2] 7c f8 [2] 70 f2 [2] 67 f9 [2] 7c b7 [2] 41 }

  condition:
    any of them
}