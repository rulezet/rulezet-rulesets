rule TTP_XOR_MULT_DOSStub_a749 {
  strings:
    $key_a749 = { f3 21 [2] 87 39 [2] c0 3b [2] 87 2a [2] c9 26 [2] c5 2c [2] d2 27 [2] c9 69 [2] f4 }

  condition:
    any of them
}