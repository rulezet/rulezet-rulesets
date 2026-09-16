rule TTP_XOR_MULT_DOSStub_a197 {
  strings:
    $key_a197 = { f5 ff [2] 81 e7 [2] c6 e5 [2] 81 f4 [2] cf f8 [2] c3 f2 [2] d4 f9 [2] cf b7 [2] f2 }

  condition:
    any of them
}