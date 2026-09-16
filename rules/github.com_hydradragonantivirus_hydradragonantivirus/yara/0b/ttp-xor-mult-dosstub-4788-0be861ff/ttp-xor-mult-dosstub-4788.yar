rule TTP_XOR_MULT_DOSStub_4788 {
  strings:
    $key_4788 = { 13 e0 [2] 67 f8 [2] 20 fa [2] 67 eb [2] 29 e7 [2] 25 ed [2] 32 e6 [2] 29 a8 [2] 14 }

  condition:
    any of them
}