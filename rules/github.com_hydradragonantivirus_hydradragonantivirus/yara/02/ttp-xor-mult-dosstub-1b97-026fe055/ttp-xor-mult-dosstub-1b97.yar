rule TTP_XOR_MULT_DOSStub_1b97 {
  strings:
    $key_1b97 = { 4f ff [2] 3b e7 [2] 7c e5 [2] 3b f4 [2] 75 f8 [2] 79 f2 [2] 6e f9 [2] 75 b7 [2] 48 }

  condition:
    any of them
}