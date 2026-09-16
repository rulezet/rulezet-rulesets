rule TTP_XOR_MULT_DOSStub_83d2 {
  strings:
    $key_83d2 = { d7 ba [2] a3 a2 [2] e4 a0 [2] a3 b1 [2] ed bd [2] e1 b7 [2] f6 bc [2] ed f2 [2] d0 }

  condition:
    any of them
}