rule TTP_XOR_MULT_DOSStub_0188 {
  strings:
    $key_0188 = { 55 e0 [2] 21 f8 [2] 66 fa [2] 21 eb [2] 6f e7 [2] 63 ed [2] 74 e6 [2] 6f a8 [2] 52 }

  condition:
    any of them
}