rule TTP_XOR_MULT_DOSStub_86d6 {
  strings:
    $key_86d6 = { d2 be [2] a6 a6 [2] e1 a4 [2] a6 b5 [2] e8 b9 [2] e4 b3 [2] f3 b8 [2] e8 f6 [2] d5 }

  condition:
    any of them
}