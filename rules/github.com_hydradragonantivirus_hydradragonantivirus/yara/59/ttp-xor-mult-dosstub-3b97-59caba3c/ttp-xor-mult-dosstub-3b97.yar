rule TTP_XOR_MULT_DOSStub_3b97 {
  strings:
    $key_3b97 = { 6f ff [2] 1b e7 [2] 5c e5 [2] 1b f4 [2] 55 f8 [2] 59 f2 [2] 4e f9 [2] 55 b7 [2] 68 }

  condition:
    any of them
}