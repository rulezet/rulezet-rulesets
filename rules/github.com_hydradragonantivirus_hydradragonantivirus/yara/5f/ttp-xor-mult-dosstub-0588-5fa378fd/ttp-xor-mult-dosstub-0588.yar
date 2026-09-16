rule TTP_XOR_MULT_DOSStub_0588 {
  strings:
    $key_0588 = { 51 e0 [2] 25 f8 [2] 62 fa [2] 25 eb [2] 6b e7 [2] 67 ed [2] 70 e6 [2] 6b a8 [2] 56 }

  condition:
    any of them
}