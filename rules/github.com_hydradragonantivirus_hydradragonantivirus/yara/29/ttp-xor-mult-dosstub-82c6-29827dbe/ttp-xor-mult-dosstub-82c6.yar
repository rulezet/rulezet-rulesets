rule TTP_XOR_MULT_DOSStub_82c6 {
  strings:
    $key_82c6 = { d6 ae [2] a2 b6 [2] e5 b4 [2] a2 a5 [2] ec a9 [2] e0 a3 [2] f7 a8 [2] ec e6 [2] d1 }

  condition:
    any of them
}