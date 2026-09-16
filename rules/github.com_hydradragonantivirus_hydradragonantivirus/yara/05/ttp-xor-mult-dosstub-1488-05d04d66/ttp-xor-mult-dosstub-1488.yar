rule TTP_XOR_MULT_DOSStub_1488 {
  strings:
    $key_1488 = { 40 e0 [2] 34 f8 [2] 73 fa [2] 34 eb [2] 7a e7 [2] 76 ed [2] 61 e6 [2] 7a a8 [2] 47 }

  condition:
    any of them
}