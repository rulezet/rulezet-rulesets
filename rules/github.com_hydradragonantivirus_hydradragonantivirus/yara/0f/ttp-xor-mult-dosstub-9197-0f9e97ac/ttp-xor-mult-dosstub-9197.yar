rule TTP_XOR_MULT_DOSStub_9197 {
  strings:
    $key_9197 = { c5 ff [2] b1 e7 [2] f6 e5 [2] b1 f4 [2] ff f8 [2] f3 f2 [2] e4 f9 [2] ff b7 [2] c2 }

  condition:
    any of them
}