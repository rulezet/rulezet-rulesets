rule TTP_XOR_MULT_DOSStub_91d6 {
  strings:
    $key_91d6 = { c5 be [2] b1 a6 [2] f6 a4 [2] b1 b5 [2] ff b9 [2] f3 b3 [2] e4 b8 [2] ff f6 [2] c2 }

  condition:
    any of them
}