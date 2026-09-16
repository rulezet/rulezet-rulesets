rule TTP_XOR_MULT_DOSStub_4188 {
  strings:
    $key_4188 = { 15 e0 [2] 61 f8 [2] 26 fa [2] 61 eb [2] 2f e7 [2] 23 ed [2] 34 e6 [2] 2f a8 [2] 12 }

  condition:
    any of them
}