rule TTP_XOR_MULT_DOSStub_8688 {
  strings:
    $key_8688 = { d2 e0 [2] a6 f8 [2] e1 fa [2] a6 eb [2] e8 e7 [2] e4 ed [2] f3 e6 [2] e8 a8 [2] d5 }

  condition:
    any of them
}