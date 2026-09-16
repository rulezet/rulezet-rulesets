rule TTP_XOR_MULT_DOSStub_8293 {
  strings:
    $key_8293 = { d6 fb [2] a2 e3 [2] e5 e1 [2] a2 f0 [2] ec fc [2] e0 f6 [2] f7 fd [2] ec b3 [2] d1 }

  condition:
    any of them
}