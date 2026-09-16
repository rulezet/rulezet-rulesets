rule TTP_XOR_MULT_DOSStub_4397 {
  strings:
    $key_4397 = { 17 ff [2] 63 e7 [2] 24 e5 [2] 63 f4 [2] 2d f8 [2] 21 f2 [2] 36 f9 [2] 2d b7 [2] 10 }

  condition:
    any of them
}