rule TTP_XOR_MULT_DOSStub_8286 {
  strings:
    $key_8286 = { d6 ee [2] a2 f6 [2] e5 f4 [2] a2 e5 [2] ec e9 [2] e0 e3 [2] f7 e8 [2] ec a6 [2] d1 }

  condition:
    any of them
}