rule TTP_XOR_MULT_DOSStub_a132 {
  strings:
    $key_a132 = { f5 5a [2] 81 42 [2] c6 40 [2] 81 51 [2] cf 5d [2] c3 57 [2] d4 5c [2] cf 12 [2] f2 }

  condition:
    any of them
}