rule TTP_XOR_MULT_DOSStub_8497 {
  strings:
    $key_8497 = { d0 ff [2] a4 e7 [2] e3 e5 [2] a4 f4 [2] ea f8 [2] e6 f2 [2] f1 f9 [2] ea b7 [2] d7 }

  condition:
    any of them
}