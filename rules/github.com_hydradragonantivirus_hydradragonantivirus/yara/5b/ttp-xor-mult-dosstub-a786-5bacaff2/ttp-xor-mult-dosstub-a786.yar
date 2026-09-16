rule TTP_XOR_MULT_DOSStub_a786 {
  strings:
    $key_a786 = { f3 ee [2] 87 f6 [2] c0 f4 [2] 87 e5 [2] c9 e9 [2] c5 e3 [2] d2 e8 [2] c9 a6 [2] f4 }

  condition:
    any of them
}