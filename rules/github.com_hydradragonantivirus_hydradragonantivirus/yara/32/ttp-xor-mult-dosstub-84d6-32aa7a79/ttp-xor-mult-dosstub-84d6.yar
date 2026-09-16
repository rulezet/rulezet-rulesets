rule TTP_XOR_MULT_DOSStub_84d6 {
  strings:
    $key_84d6 = { d0 be [2] a4 a6 [2] e3 a4 [2] a4 b5 [2] ea b9 [2] e6 b3 [2] f1 b8 [2] ea f6 [2] d7 }

  condition:
    any of them
}