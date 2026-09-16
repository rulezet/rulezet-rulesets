rule TTP_XOR_MULT_DOSStub_a18d {
  strings:
    $key_a18d = { f5 e5 [2] 81 fd [2] c6 ff [2] 81 ee [2] cf e2 [2] c3 e8 [2] d4 e3 [2] cf ad [2] f2 }

  condition:
    any of them
}