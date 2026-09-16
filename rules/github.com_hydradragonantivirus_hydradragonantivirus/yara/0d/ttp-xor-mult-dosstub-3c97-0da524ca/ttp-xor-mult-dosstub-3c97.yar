rule TTP_XOR_MULT_DOSStub_3c97 {
  strings:
    $key_3c97 = { 68 ff [2] 1c e7 [2] 5b e5 [2] 1c f4 [2] 52 f8 [2] 5e f2 [2] 49 f9 [2] 52 b7 [2] 6f }

  condition:
    any of them
}