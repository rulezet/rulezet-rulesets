rule TTP_XOR_MULT_DOSStub_4088 {
  strings:
    $key_4088 = { 14 e0 [2] 60 f8 [2] 27 fa [2] 60 eb [2] 2e e7 [2] 22 ed [2] 35 e6 [2] 2e a8 [2] 13 }

  condition:
    any of them
}