rule TTP_XOR_MULT_DOSStub_81c6 {
  strings:
    $key_81c6 = { d5 ae [2] a1 b6 [2] e6 b4 [2] a1 a5 [2] ef a9 [2] e3 a3 [2] f4 a8 [2] ef e6 [2] d2 }

  condition:
    any of them
}