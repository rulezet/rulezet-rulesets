rule TTP_XOR_MULT_DOSStub_94d2 {
  strings:
    $key_94d2 = { c0 ba [2] b4 a2 [2] f3 a0 [2] b4 b1 [2] fa bd [2] f6 b7 [2] e1 bc [2] fa f2 [2] c7 }

  condition:
    any of them
}