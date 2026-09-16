rule TTP_XOR_MULT_DOSStub_4186 {
  strings:
    $key_4186 = { 15 ee [2] 61 f6 [2] 26 f4 [2] 61 e5 [2] 2f e9 [2] 23 e3 [2] 34 e8 [2] 2f a6 [2] 12 }

  condition:
    any of them
}