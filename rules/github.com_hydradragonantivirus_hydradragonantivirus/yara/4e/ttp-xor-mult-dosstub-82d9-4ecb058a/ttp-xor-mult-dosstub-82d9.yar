rule TTP_XOR_MULT_DOSStub_82d9 {
  strings:
    $key_82d9 = { d6 b1 [2] a2 a9 [2] e5 ab [2] a2 ba [2] ec b6 [2] e0 bc [2] f7 b7 [2] ec f9 [2] d1 }

  condition:
    any of them
}