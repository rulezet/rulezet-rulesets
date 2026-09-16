rule TTP_XOR_MULT_DOSStub_5297 {
  strings:
    $key_5297 = { 06 ff [2] 72 e7 [2] 35 e5 [2] 72 f4 [2] 3c f8 [2] 30 f2 [2] 27 f9 [2] 3c b7 [2] 01 }

  condition:
    any of them
}