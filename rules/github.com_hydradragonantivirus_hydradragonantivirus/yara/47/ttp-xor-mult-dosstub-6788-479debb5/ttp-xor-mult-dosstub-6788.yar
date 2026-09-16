rule TTP_XOR_MULT_DOSStub_6788 {
  strings:
    $key_6788 = { 33 e0 [2] 47 f8 [2] 00 fa [2] 47 eb [2] 09 e7 [2] 05 ed [2] 12 e6 [2] 09 a8 [2] 34 }

  condition:
    any of them
}