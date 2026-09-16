rule TTP_XOR_MULT_DOSStub_959a {
  strings:
    $key_959a = { c1 f2 [2] b5 ea [2] f2 e8 [2] b5 f9 [2] fb f5 [2] f7 ff [2] e0 f4 [2] fb ba [2] c6 }

  condition:
    any of them
}