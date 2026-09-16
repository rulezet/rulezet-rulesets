rule TTP_XOR_MULT_DOSStub_84d2 {
  strings:
    $key_84d2 = { d0 ba [2] a4 a2 [2] e3 a0 [2] a4 b1 [2] ea bd [2] e6 b7 [2] f1 bc [2] ea f2 [2] d7 }

  condition:
    any of them
}