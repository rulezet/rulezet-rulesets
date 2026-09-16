rule TTP_XOR_MULT_DOSStub_7b97 {
  strings:
    $key_7b97 = { 2f ff [2] 5b e7 [2] 1c e5 [2] 5b f4 [2] 15 f8 [2] 19 f2 [2] 0e f9 [2] 15 b7 [2] 28 }

  condition:
    any of them
}