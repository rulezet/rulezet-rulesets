rule TTP_XOR_MULT_DOSStub_a1e9 {
  strings:
    $key_a1e9 = { f5 81 [2] 81 99 [2] c6 9b [2] 81 8a [2] cf 86 [2] c3 8c [2] d4 87 [2] cf c9 [2] f2 }

  condition:
    any of them
}