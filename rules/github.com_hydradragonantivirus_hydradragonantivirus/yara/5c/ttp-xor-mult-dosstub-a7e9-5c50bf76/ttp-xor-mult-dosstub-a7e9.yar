rule TTP_XOR_MULT_DOSStub_a7e9 {
  strings:
    $key_a7e9 = { f3 81 [2] 87 99 [2] c0 9b [2] 87 8a [2] c9 86 [2] c5 8c [2] d2 87 [2] c9 c9 [2] f4 }

  condition:
    any of them
}