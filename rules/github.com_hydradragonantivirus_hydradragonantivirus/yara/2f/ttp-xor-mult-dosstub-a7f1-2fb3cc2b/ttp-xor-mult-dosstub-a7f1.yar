rule TTP_XOR_MULT_DOSStub_a7f1 {
  strings:
    $key_a7f1 = { f3 99 [2] 87 81 [2] c0 83 [2] 87 92 [2] c9 9e [2] c5 94 [2] d2 9f [2] c9 d1 [2] f4 }

  condition:
    any of them
}