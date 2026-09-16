rule TTP_XOR_MULT_DOSStub_83b9 {
  strings:
    $key_83b9 = { d7 d1 [2] a3 c9 [2] e4 cb [2] a3 da [2] ed d6 [2] e1 dc [2] f6 d7 [2] ed 99 [2] d0 }

  condition:
    any of them
}