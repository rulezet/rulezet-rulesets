rule TTP_XOR_MULT_DOSStub_2297 {
  strings:
    $key_2297 = { 76 ff [2] 02 e7 [2] 45 e5 [2] 02 f4 [2] 4c f8 [2] 40 f2 [2] 57 f9 [2] 4c b7 [2] 71 }

  condition:
    any of them
}