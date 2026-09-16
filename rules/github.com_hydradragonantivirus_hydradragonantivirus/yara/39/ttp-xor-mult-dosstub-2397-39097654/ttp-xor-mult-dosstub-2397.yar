rule TTP_XOR_MULT_DOSStub_2397 {
  strings:
    $key_2397 = { 77 ff [2] 03 e7 [2] 44 e5 [2] 03 f4 [2] 4d f8 [2] 41 f2 [2] 56 f9 [2] 4d b7 [2] 70 }

  condition:
    any of them
}