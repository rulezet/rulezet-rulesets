rule TTP_XOR_MULT_DOSStub_a119 {
  strings:
    $key_a119 = { f5 71 [2] 81 69 [2] c6 6b [2] 81 7a [2] cf 76 [2] c3 7c [2] d4 77 [2] cf 39 [2] f2 }

  condition:
    any of them
}