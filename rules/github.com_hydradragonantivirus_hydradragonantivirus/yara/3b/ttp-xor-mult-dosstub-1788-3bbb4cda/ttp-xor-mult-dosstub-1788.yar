rule TTP_XOR_MULT_DOSStub_1788 {
  strings:
    $key_1788 = { 43 e0 [2] 37 f8 [2] 70 fa [2] 37 eb [2] 79 e7 [2] 75 ed [2] 62 e6 [2] 79 a8 [2] 44 }

  condition:
    any of them
}