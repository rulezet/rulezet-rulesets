rule TTP_XOR_MULT_DOSStub_4b97 {
  strings:
    $key_4b97 = { 1f ff [2] 6b e7 [2] 2c e5 [2] 6b f4 [2] 25 f8 [2] 29 f2 [2] 3e f9 [2] 25 b7 [2] 18 }

  condition:
    any of them
}