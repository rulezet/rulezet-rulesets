rule TTP_XOR_MULT_DOSStub_2286 {
  strings:
    $key_2286 = { 76 ee [2] 02 f6 [2] 45 f4 [2] 02 e5 [2] 4c e9 [2] 40 e3 [2] 57 e8 [2] 4c a6 [2] 71 }

  condition:
    any of them
}