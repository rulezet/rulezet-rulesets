rule TTP_XOR_MULT_DOSStub_a732 {
  strings:
    $key_a732 = { f3 5a [2] 87 42 [2] c0 40 [2] 87 51 [2] c9 5d [2] c5 57 [2] d2 5c [2] c9 12 [2] f4 }

  condition:
    any of them
}