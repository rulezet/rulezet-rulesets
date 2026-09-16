rule TTP_XOR_MULT_DOSStub_82d6 {
  strings:
    $key_82d6 = { d6 be [2] a2 a6 [2] e5 a4 [2] a2 b5 [2] ec b9 [2] e0 b3 [2] f7 b8 [2] ec f6 [2] d1 }

  condition:
    any of them
}