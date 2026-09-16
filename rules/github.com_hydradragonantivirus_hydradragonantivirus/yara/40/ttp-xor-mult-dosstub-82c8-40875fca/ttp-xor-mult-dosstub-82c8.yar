rule TTP_XOR_MULT_DOSStub_82c8 {
  strings:
    $key_82c8 = { d6 a0 [2] a2 b8 [2] e5 ba [2] a2 ab [2] ec a7 [2] e0 ad [2] f7 a6 [2] ec e8 [2] d1 }

  condition:
    any of them
}