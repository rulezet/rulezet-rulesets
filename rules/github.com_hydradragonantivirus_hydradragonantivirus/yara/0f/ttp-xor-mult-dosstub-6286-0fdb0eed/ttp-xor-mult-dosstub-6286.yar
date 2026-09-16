rule TTP_XOR_MULT_DOSStub_6286 {
  strings:
    $key_6286 = { 36 ee [2] 42 f6 [2] 05 f4 [2] 42 e5 [2] 0c e9 [2] 00 e3 [2] 17 e8 [2] 0c a6 [2] 31 }

  condition:
    any of them
}