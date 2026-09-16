rule TTP_XOR_MULT_DOSStub_7788 {
  strings:
    $key_7788 = { 23 e0 [2] 57 f8 [2] 10 fa [2] 57 eb [2] 19 e7 [2] 15 ed [2] 02 e6 [2] 19 a8 [2] 24 }

  condition:
    any of them
}