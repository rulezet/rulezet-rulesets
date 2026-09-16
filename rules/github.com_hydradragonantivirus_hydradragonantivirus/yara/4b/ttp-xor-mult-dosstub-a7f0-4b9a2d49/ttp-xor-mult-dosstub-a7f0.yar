rule TTP_XOR_MULT_DOSStub_a7f0 {
  strings:
    $key_a7f0 = { f3 98 [2] 87 80 [2] c0 82 [2] 87 93 [2] c9 9f [2] c5 95 [2] d2 9e [2] c9 d0 [2] f4 }

  condition:
    any of them
}