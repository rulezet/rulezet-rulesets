rule TTP_XOR_MULT_DOSStub_5288 {
  strings:
    $key_5288 = { 06 e0 [2] 72 f8 [2] 35 fa [2] 72 eb [2] 3c e7 [2] 30 ed [2] 27 e6 [2] 3c a8 [2] 01 }

  condition:
    any of them
}