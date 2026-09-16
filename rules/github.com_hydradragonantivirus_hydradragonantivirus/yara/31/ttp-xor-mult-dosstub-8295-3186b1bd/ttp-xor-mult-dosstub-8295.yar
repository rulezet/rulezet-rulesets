rule TTP_XOR_MULT_DOSStub_8295 {
  strings:
    $key_8295 = { d6 fd [2] a2 e5 [2] e5 e7 [2] a2 f6 [2] ec fa [2] e0 f0 [2] f7 fb [2] ec b5 [2] d1 }

  condition:
    any of them
}