rule TTP_XOR_MULT_DOSStub_0b97 {
  strings:
    $key_0b97 = { 5f ff [2] 2b e7 [2] 6c e5 [2] 2b f4 [2] 65 f8 [2] 69 f2 [2] 7e f9 [2] 65 b7 [2] 58 }

  condition:
    any of them
}