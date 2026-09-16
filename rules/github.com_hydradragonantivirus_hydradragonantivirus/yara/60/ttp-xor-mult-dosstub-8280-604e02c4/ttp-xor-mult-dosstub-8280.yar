rule TTP_XOR_MULT_DOSStub_8280 {
  strings:
    $key_8280 = { d6 e8 [2] a2 f0 [2] e5 f2 [2] a2 e3 [2] ec ef [2] e0 e5 [2] f7 ee [2] ec a0 [2] d1 }

  condition:
    any of them
}