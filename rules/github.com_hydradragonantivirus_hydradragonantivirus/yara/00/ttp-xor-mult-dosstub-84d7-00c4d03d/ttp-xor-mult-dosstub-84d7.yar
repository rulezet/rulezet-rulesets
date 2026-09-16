rule TTP_XOR_MULT_DOSStub_84d7 {
  strings:
    $key_84d7 = { d0 bf [2] a4 a7 [2] e3 a5 [2] a4 b4 [2] ea b8 [2] e6 b2 [2] f1 b9 [2] ea f7 [2] d7 }

  condition:
    any of them
}