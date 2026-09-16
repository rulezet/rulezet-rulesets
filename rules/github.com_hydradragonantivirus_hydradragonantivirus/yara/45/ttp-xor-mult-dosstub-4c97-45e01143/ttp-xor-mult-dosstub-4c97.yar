rule TTP_XOR_MULT_DOSStub_4c97 {
  strings:
    $key_4c97 = { 18 ff [2] 6c e7 [2] 2b e5 [2] 6c f4 [2] 22 f8 [2] 2e f2 [2] 39 f9 [2] 22 b7 [2] 1f }

  condition:
    any of them
}