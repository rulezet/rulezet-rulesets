rule TTP_XOR_MULT_DOSStub_6c97 {
  strings:
    $key_6c97 = { 38 ff [2] 4c e7 [2] 0b e5 [2] 4c f4 [2] 02 f8 [2] 0e f2 [2] 19 f9 [2] 02 b7 [2] 3f }

  condition:
    any of them
}