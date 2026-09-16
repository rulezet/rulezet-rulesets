rule TTP_XOR_MULT_DOSStub_a4f6 {
  strings:
    $key_a4f6 = { f0 9e [2] 84 86 [2] c3 84 [2] 84 95 [2] ca 99 [2] c6 93 [2] d1 98 [2] ca d6 [2] f7 }

  condition:
    any of them
}