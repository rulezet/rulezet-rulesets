rule TTP_XOR_MULT_DOSStub_8186 {
  strings:
    $key_8186 = { d5 ee [2] a1 f6 [2] e6 f4 [2] a1 e5 [2] ef e9 [2] e3 e3 [2] f4 e8 [2] ef a6 [2] d2 }

  condition:
    any of them
}