rule TTP_XOR_MULT_DOSStub_82d2 {
  strings:
    $key_82d2 = { d6 ba [2] a2 a2 [2] e5 a0 [2] a2 b1 [2] ec bd [2] e0 b7 [2] f7 bc [2] ec f2 [2] d1 }

  condition:
    any of them
}