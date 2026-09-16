rule TTP_XOR_MULT_DOSStub_1c97 {
  strings:
    $key_1c97 = { 48 ff [2] 3c e7 [2] 7b e5 [2] 3c f4 [2] 72 f8 [2] 7e f2 [2] 69 f9 [2] 72 b7 [2] 4f }

  condition:
    any of them
}