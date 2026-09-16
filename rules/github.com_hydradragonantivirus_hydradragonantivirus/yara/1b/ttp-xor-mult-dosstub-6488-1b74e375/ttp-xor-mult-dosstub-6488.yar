rule TTP_XOR_MULT_DOSStub_6488 {
  strings:
    $key_6488 = { 30 e0 [2] 44 f8 [2] 03 fa [2] 44 eb [2] 0a e7 [2] 06 ed [2] 11 e6 [2] 0a a8 [2] 37 }

  condition:
    any of them
}