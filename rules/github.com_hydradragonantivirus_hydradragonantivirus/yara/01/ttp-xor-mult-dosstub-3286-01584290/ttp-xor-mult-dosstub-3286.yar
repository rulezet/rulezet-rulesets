rule TTP_XOR_MULT_DOSStub_3286 {
  strings:
    $key_3286 = { 66 ee [2] 12 f6 [2] 55 f4 [2] 12 e5 [2] 5c e9 [2] 50 e3 [2] 47 e8 [2] 5c a6 [2] 61 }

  condition:
    any of them
}