rule TTP_XOR_MULT_DOSStub_3186 {
  strings:
    $key_3186 = { 65 ee [2] 11 f6 [2] 56 f4 [2] 11 e5 [2] 5f e9 [2] 53 e3 [2] 44 e8 [2] 5f a6 [2] 62 }

  condition:
    any of them
}