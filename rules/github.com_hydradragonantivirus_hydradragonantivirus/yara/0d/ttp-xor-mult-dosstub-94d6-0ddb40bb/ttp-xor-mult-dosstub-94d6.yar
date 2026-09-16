rule TTP_XOR_MULT_DOSStub_94d6 {
  strings:
    $key_94d6 = { c0 be [2] b4 a6 [2] f3 a4 [2] b4 b5 [2] fa b9 [2] f6 b3 [2] e1 b8 [2] fa f6 [2] c7 }

  condition:
    any of them
}