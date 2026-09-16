rule TTP_XOR_MULT_DOSStub_a7f6 {
  strings:
    $key_a7f6 = { f3 9e [2] 87 86 [2] c0 84 [2] 87 95 [2] c9 99 [2] c5 93 [2] d2 98 [2] c9 d6 [2] f4 }

  condition:
    any of them
}