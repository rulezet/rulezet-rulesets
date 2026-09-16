rule TTP_XOR_MULT_DOSStub_2188 {
  strings:
    $key_2188 = { 75 e0 [2] 01 f8 [2] 46 fa [2] 01 eb [2] 4f e7 [2] 43 ed [2] 54 e6 [2] 4f a8 [2] 72 }

  condition:
    any of them
}