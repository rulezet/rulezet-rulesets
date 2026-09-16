rule TTP_XOR_MULT_DOSStub_a1e4 {
  strings:
    $key_a1e4 = { f5 8c [2] 81 94 [2] c6 96 [2] 81 87 [2] cf 8b [2] c3 81 [2] d4 8a [2] cf c4 [2] f2 }

  condition:
    any of them
}