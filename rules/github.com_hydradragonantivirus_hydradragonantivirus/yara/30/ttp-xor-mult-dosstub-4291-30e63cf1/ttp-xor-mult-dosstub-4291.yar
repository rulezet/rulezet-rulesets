rule TTP_XOR_MULT_DOSStub_4291 {
  strings:
    $key_4291 = { 16 f9 [2] 62 e1 [2] 25 e3 [2] 62 f2 [2] 2c fe [2] 20 f4 [2] 37 ff [2] 2c b1 [2] 11 }

  condition:
    any of them
}